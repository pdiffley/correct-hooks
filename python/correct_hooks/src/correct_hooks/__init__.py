from __future__ import annotations

import asyncio
import base64
import time
import uuid

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
  Ed25519PrivateKey,
  Ed25519PublicKey,
)
from pydantic import UUID4, AnyUrl, BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

SIGNATURE_VERSION = "v1"
"""The signature version produced by this version of the library."""

_DEFAULT_SIGNATURE_TTL_SECONDS = 300
_DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS = 300

VALID_HTTP_METHODS = frozenset(
  {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
  }
)


class CamelCaseBaseModel(BaseModel):
  model_config = ConfigDict(
    alias_generator=to_camel,
    validate_by_name=True,
    serialize_by_alias=True,
    strict=True,
  )


class SecretSigningKey(CamelCaseBaseModel):
  """A key used to sign requests.

  Must be kept secret and should only be held by the signer.
  """

  kid: UUID4 = Field(strict=False)
  kty: str
  crv: str
  x: str
  d: str


class _PublicJwk(CamelCaseBaseModel):
  kid: UUID4 = Field(strict=False)
  kty: str
  crv: str
  x: str


class PublicVerifyingKeySet(CamelCaseBaseModel):
  """A set of public keys used to verify signed requests."""

  keys: list[_PublicJwk]


class _SignatureComponents(CamelCaseBaseModel):
  webhook_id: UUID4 = Field(strict=False)
  key_id: UUID4 = Field(strict=False)
  signed_at: int


class InvalidKeyFound(Exception):
  pass


class SignArgs(CamelCaseBaseModel):
  webhook_id: UUID4 = Field(strict=False)
  recipient_id: UUID4 = Field(strict=False)
  target_url: AnyUrl = Field(strict=False)
  method: str
  request_body: bytes
  secret_signing_key: SecretSigningKey

class SignatureData(CamelCaseBaseModel):
  """Header values to set on the webhook request.
  You must set the request headers `correct-hooks-signature-components` and `correct-hooks-signature` to these values.
  Webhook consumers will pass the values of the headers to the verify function. Future versions of Correct Hooks with
  convenience functions that verify specific framework's request objects will expect these exact header names to be set.
  """

  correct_hooks_signature_components: str
  """Set the header `correct-hooks-signature-components` to this value."""
  correct_hooks_signature: str
  """Set the header `correct-hooks-signature` to this value."""


class InvalidArgs(Exception):
  pass


class InvalidSigningKey(Exception):
  pass


class VerifyArgs(CamelCaseBaseModel):
  target_url: AnyUrl = Field(strict=False)
  method: str
  correct_hooks_signature_components: str
  correct_hooks_signature: str
  request_body: bytes


class VerifiedData(CamelCaseBaseModel):
  """Validated request data."""

  webhook_id: UUID4
  """The validated `webhook_id` for the request. These id's can be put in a shared cache
  by the webhook consumer and checked against for the highest level of replay protection.
  """


class PublicVerifyingKeyNotFound(Exception):
  """The key needed to verify the request was not found in the verifying key set provided by the
  webhook provider.

  If you receive this error consistently, the webhook provider may need to update their
  published public verifying key set. In some specific cases, this error can also be returned
  due to an invalid signature.
  """


class PublicVerifyingKeyRetrievalFailed(Exception):
  """The webhook provider's public verifying key set could not be retrieved.

  If you get this error, likely either the `public_verifying_key_set_url` the `Verifier` was created with is incorrect,
  or the webhook producer's endpoint is unavailable.
  """


class InvalidSignature(Exception):
  pass


class InvalidPublicVerifyingKey(Exception):
  """The public verifying key set retrieved from `public_verifying_key_set_url` could not be parsed and likely
  needs to be updated by the webhook producer.
  """


def generate_secret_signing_key() -> SecretSigningKey:
  """Generate a new `SecretSigningKey`."""
  key_id = uuid.uuid4()
  signing_key = Ed25519PrivateKey.generate()
  secret_key = _encode_base64(signing_key.private_bytes_raw())
  public_key = _encode_base64(signing_key.public_key().public_bytes_raw())
  jwk = SecretSigningKey(
    kid=key_id,
    kty="OKP",
    crv="Ed25519",
    x=public_key,
    d=secret_key,
  )
  return jwk


def create_public_verifying_key_set(
  secret_signing_keys: list[SecretSigningKey],
) -> PublicVerifyingKeySet:
  """Creates a `PublicVerifyingKeySet` from a list of `SecretSigningKey`.

  The returned `PublicVerifyingKeySet` can be used to verify requests signed
  by any of the `secret_signing_keys`.

  Args:
    secret_signing_keys: The `SecretSigningKey`s to create the `PublicVerifyingKeySet` from.

  Raises:
    InvalidKeyFound
  """
  public_jwks = PublicVerifyingKeySet(keys=[])
  for private_key in secret_signing_keys:
    try:
      public_key = _PublicJwk.model_validate(private_key.model_dump())
      public_jwks.keys.append(public_key)
    except Exception as e:
      raise InvalidKeyFound from e
  return public_jwks


def sign(
  args: SignArgs
) -> SignatureData:
  """Creates a signature for a webhook request and returns the signature headers that should be set on the request.

  You must set the request headers `correct-hooks-signature-components` and `correct-hooks-signature` to these values.
  Webhook consumers will pass the values of the headers to the verify function. Future versions of Correct Hooks with
  convenience functions that verify specific framework's request objects will expect these exact header names to be set.


  `sign` should be called every time a webhook delivery is attempted. The signed headers should not be reused
  between retried delivery attempts.

  Args:
    webhook_id: An id for the webhook.
      This id should be unique for the event triggering the webhook, and should
      be reused for any delivery retries.
    recipient_id: The webhook consumer's id.
      This id must be provided by the webhook producer, and not taken as an input from the webhook consumer.
    target_url: The url the webhook is being sent to.
      Must be the exact url string provided by the webhook consumer.
    method: The HTTP method the webhook will be sent with.
    request_body: The exact body of the webhook request as bytes.
    secret_signing_key: The `SecretSigningKey` the signature will be signed with.

  Raises:
    InvalidArgs
    InvalidSigningKey
  """
  if not is_valid_http_method(args.method):
    raise InvalidArgs

  key_id = args.secret_signing_key.kid
  signed_at = _seconds_since_unix_epoch()

  signature_components = _SignatureComponents(
    webhook_id=args.webhook_id,
    key_id=key_id,
    signed_at=signed_at,
  )

  encoded_signature_components = _encode_signature_components(signature_components)
  signature_components_header = _version_header_value(encoded_signature_components)

  try:
    secret_key_bytes = decode_base64(args.secret_signing_key.d)
    signing_key = Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
  except Exception as e:
    raise InvalidSigningKey from e

  signature_message = _construct_signature_message(
    signature_components,
    args.recipient_id,
    args.target_url,
    args.method,
    args.request_body,
  )

  signature = signing_key.sign(signature_message)
  signature_base64 = _encode_base64(signature)
  signature_header_value = _version_header_value(signature_base64)

  return SignatureData(
    correct_hooks_signature_components=signature_components_header,
    correct_hooks_signature=signature_header_value,
  )


class Verifier:
  """Verifier for signed webhook requests

  The `Verifier` handles retrieving and refreshing the webhook producer's verifying key set for you.

  Ideally you should create one `Verifier` when your backend instance starts and reuse it for all requests sent to that backend instance.
  """

  def __init__(
    self,
    *,
    recipient_id: uuid.UUID,
    public_verifying_key_set_url: str,
    signature_ttl_seconds: int | None = None,
    public_verifying_key_set_ttl_seconds: int | None = None,
  ) -> None:
    """Create a new `Verifier`.

    Args:
      recipient_id: Your webhook consumer id.
        This id must be provided to you in advance by the webhook producer and should never be extracted
        from a webhook request.
      public_verifying_key_set_url: The url serving the webhook provider's verfiying key set.
        The webhook provider should give you this url.
      signature_ttl_seconds: How long a signature is considered valid. Defaults to 300 seconds (5 minutes).
        In most cases, the default parameter should be used.
        This parameter should not be set to a value larger than 300 (may be enforced in the future).
      public_verifying_key_set_ttl_seconds: How long a retrieved `public_verifying_key_set` can be used before it is considered stale. Defaults to 300 seconds (5 minutes).
        In most cases, the default parameter should be used.
        This parameter should not be set to a value larger than 300 (may be enforced in the future).
    """
    self._recipient_id = recipient_id
    self._public_verifying_key_set_url = public_verifying_key_set_url
    if signature_ttl_seconds is not None:
      self._signature_ttl_seconds = signature_ttl_seconds
    else:
      self._signature_ttl_seconds = _DEFAULT_SIGNATURE_TTL_SECONDS
    if public_verifying_key_set_ttl_seconds is not None:
      self._public_verifying_key_set_ttl_seconds = public_verifying_key_set_ttl_seconds
    else:
      self._public_verifying_key_set_ttl_seconds = (
        _DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS
      )

    self._public_verifying_key_set = PublicVerifyingKeySet(keys=[])
    self._public_verifying_key_set_refreshed_at = 0
    self._public_verifying_key_set_refresh_id = uuid.uuid4()
    self._public_verifying_key_set_refresh_lock = asyncio.Lock()

  async def verify(
    self,
    args: VerifyArgs
  ) -> VerifiedData:
    """Verifies a request and returns validated information from the Correct Hooks request headers.

    This function confirms that the provided request signature is valid, that the signature has not expired, and that the request was sent to the intended endpoint.

    Any raised error indicates that the signature could not be verified and the request should be rejected with a 4xx error

    Args:
    target_url: The url your endpoint is receiving requests at.
      `target_url` needs to be the exact string given to the webhook provider,
      preferably retrieved from an environment variable or hardcoded.
    method: The HTTP method the request was sent with. Can be extracted from the request.
    correct_hooks_signature_components: The value from the request's `correct-hooks-signature-components` header.
    correct_hooks_signature: The value from the request's `correct-hooks-signature` header.
    request_body: The unparsed request body as bytes.

    Raises:
      PublicVerifyingKeyNotFound
      PublicVerifyingKeyRetrievalFailed
      InvalidSignature
      InvalidPublicVerifyingKey
    """
    now = _seconds_since_unix_epoch()
    return await self.verify_with_time(
      args=args,
      now=now,
    )

  async def verify_with_time(
    self,
    args: VerifyArgs,
    now: int,
  ) -> VerifiedData:
    """The same as `Verifier.verify` but with the current time provided by the caller, which
    can be useful for testing.

    Args:
    now: The current time in seconds since Unix epoch.
    """
    if (
      now
      > self._public_verifying_key_set_refreshed_at
      + self._public_verifying_key_set_ttl_seconds
    ):
      try:
        await self._refresh_jwks(self._public_verifying_key_set_refresh_id)
      except Exception:  # noqa
        pass
    try:
      return verify_with_time(
        args=args,
        recipient_id=self._recipient_id,
        signature_ttl_seconds=self._signature_ttl_seconds,
        public_verifying_key_set=self._public_verifying_key_set,
        now=now,
      )
    except PublicVerifyingKeyNotFound:
      try:
        await self._refresh_jwks(self._public_verifying_key_set_refresh_id)
      except Exception:  # noqa
        raise PublicVerifyingKeyRetrievalFailed()
      return verify_with_time(
        args=args,
        recipient_id=self._recipient_id,
        signature_ttl_seconds=self._signature_ttl_seconds,
        public_verifying_key_set=self._public_verifying_key_set,
        now=now,
      )

  def verify_sync(
    self,
    args: VerifyArgs
  ) -> VerifiedData:
    """A synchronous version of `Verifier.verify`."""
    now = _seconds_since_unix_epoch()
    return self.verify_with_time_sync(
      args=args,
      now=now,
    )

  def verify_with_time_sync(
    self,
    args: VerifyArgs,
    now: int,
  ) -> VerifiedData:
    """A synchronous version of `Verifier.verify_with_time`."""
    if (
      now
      > self._public_verifying_key_set_refreshed_at
      + self._public_verifying_key_set_ttl_seconds
    ):
      try:
        self._refresh_jwks_sync()
      except Exception:  # noqa
        pass
    try:
      return verify_with_time(
        args=args,
        recipient_id=self._recipient_id,
        signature_ttl_seconds=self._signature_ttl_seconds,
        public_verifying_key_set=self._public_verifying_key_set,
        now=now,
      )
    except PublicVerifyingKeyNotFound:
      try:
        self._refresh_jwks_sync()
      except Exception:  # noqa
        raise PublicVerifyingKeyRetrievalFailed()
      result = verify_with_time(
        args=args,
        recipient_id=self._recipient_id,
        signature_ttl_seconds=self._signature_ttl_seconds,
        public_verifying_key_set=self._public_verifying_key_set,
        now=now,
      )
      return result

  async def _refresh_jwks(self, old_refresh_id: uuid.UUID) -> None:
    async with self._public_verifying_key_set_refresh_lock:
      if self._public_verifying_key_set_refresh_id != old_refresh_id:
        return
      async with httpx.AsyncClient() as client:
        response = await client.get(self._public_verifying_key_set_url)
      if response.status_code != 200:
        raise PublicVerifyingKeyRetrievalFailed()
      self._public_verifying_key_set = PublicVerifyingKeySet.model_validate_json(
        response.content
      )
      self._public_verifying_key_set_refreshed_at = _seconds_since_unix_epoch()
      self._public_verifying_key_set_refresh_id = uuid.uuid4()

  def _refresh_jwks_sync(self) -> None:
    new_refresh_time = _seconds_since_unix_epoch()
    with httpx.Client() as client:
      response = client.get(self._public_verifying_key_set_url)
    if response.status_code != 200:
      raise PublicVerifyingKeyRetrievalFailed()
    self._public_verifying_key_set = PublicVerifyingKeySet.model_validate_json(
      response.content
    )
    self._public_verifying_key_set_refreshed_at = new_refresh_time


def verify_with_time(
  *,
  args: VerifyArgs,
  recipient_id: uuid.UUID,
  signature_ttl_seconds: int,
  public_verifying_key_set: PublicVerifyingKeySet,
  now: int,
) -> VerifiedData:
  """This function is only public for internal testing purposes and will be made private in a future version of this library."""

  signature_components_encoded = _split_versioned_header(
    args.correct_hooks_signature_components
  ).get(SIGNATURE_VERSION)
  if signature_components_encoded is None:
    raise InvalidSignature()
  try:
    signature_components = _decode_signature_components(signature_components_encoded)
  except Exception as e:
    raise InvalidSignature() from e

  if (
    now > signature_components.signed_at + signature_ttl_seconds
    or now + signature_ttl_seconds < signature_components.signed_at
  ):
    raise InvalidSignature()

  verifying_key_jwk = next(
    (
      key
      for key in public_verifying_key_set.keys
      if key.kid == signature_components.key_id
    ),
    None,
  )

  if verifying_key_jwk is None:
    raise PublicVerifyingKeyNotFound()

  try:
    public_key_bytes = decode_base64(verifying_key_jwk.x)
    verifying_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
  except Exception as e:
    raise InvalidPublicVerifyingKey() from e

  signature_message = _construct_signature_message(
    signature_components,
    recipient_id,
    args.target_url,
    args.method,
    args.request_body,
  )

  signature_encoded = _split_versioned_header(args.correct_hooks_signature).get(
    SIGNATURE_VERSION
  )
  if signature_encoded is None:
    raise InvalidSignature()

  try:
    signature_bytes = decode_base64(signature_encoded)
  except Exception as e:
    raise InvalidSignature() from e

  try:
    verifying_key.verify(signature_bytes, signature_message)
  except Exception as e:
    raise InvalidSignature() from e

  return VerifiedData(webhook_id=signature_components.webhook_id)


def _construct_signature_message(
  signature_components: _SignatureComponents,
  recipient_id: uuid.UUID,
  target_url: AnyUrl,
  method: str,
  request_body: bytes,
) -> bytes:
  encoded_signature_components = _encode_signature_components(signature_components)
  recipient_id_base64 = _encode_base64_from_string(str(recipient_id))
  target_url_base64 = _encode_base64_from_string(str(target_url))
  signature_components_bytes = f"{encoded_signature_components}.{recipient_id_base64}.{target_url_base64},{method}.".encode()
  return signature_components_bytes + request_body


def _version_header_value(header_value: str) -> str:
  return f"{SIGNATURE_VERSION},{header_value}"


def _split_versioned_header(header: str) -> dict[str, str]:
  split_headers: dict[str, str] = {}
  for versioned_value in header.split(" "):
    parts = versioned_value.split(",")
    if len(parts) < 2:
      continue
    split_headers[parts[0]] = parts[1]
  return split_headers


def _encode_signature_components(signature_components: _SignatureComponents) -> str:
  webhook_id_base64 = _encode_base64_from_string(str(signature_components.webhook_id))
  key_id_base64 = _encode_base64_from_string(str(signature_components.key_id))
  signed_at_base64 = _encode_base64_from_string(str(signature_components.signed_at))
  encoded_signature_components = f"{webhook_id_base64}.{key_id_base64}.{signed_at_base64}"
  return encoded_signature_components


def _decode_signature_components(
  encoded_signature_components: str,
) -> _SignatureComponents:
  components = list(encoded_signature_components.split("."))
  if len(components) != 3:
    raise ValueError("Invalid component count")
  webhook_id = uuid.UUID(_decode_base64_to_string(components[0]))
  key_id = uuid.UUID(_decode_base64_to_string(components[1]))
  signed_at = int(_decode_base64_to_string(components[2]))
  return _SignatureComponents(
    webhook_id=webhook_id,
    key_id=key_id,
    signed_at=signed_at,
  )


def is_valid_http_method(method: str) -> bool:
  return method in VALID_HTTP_METHODS


def _encode_base64(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def decode_base64(base64_string: str) -> bytes:
  """This function is only public for internal testing purposes and will be made private in a future version of this library."""
  return base64.urlsafe_b64decode(base64_string + "===")


def _encode_base64_from_string(data: str) -> str:
  return _encode_base64(data.encode("utf-8"))


def _decode_base64_to_string(base64_string: str) -> str:
  return decode_base64(base64_string).decode("utf-8")


def _seconds_since_unix_epoch() -> int:
  return int(time.time())
