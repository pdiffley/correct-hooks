from __future__ import annotations

import base64
import time
import uuid

import httpx
from cryptography.exceptions import InvalidSignature as CrytpographyInvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
  Ed25519PrivateKey,
  Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

SIGNATURE_VERSION = "v1"

_SECRET_KEY_LENGTH = 32
_PUBLIC_KEY_LENGTH = 32
_SIGNATURE_LENGTH = 64


class CamelCaseBaseModel(BaseModel):
  model_config = ConfigDict(
    alias_generator=to_camel,
    validate_by_name=True,
    serialize_by_alias=True,
    strict=True,
  )


class SecretSigningKey(CamelCaseBaseModel):
  kid: uuid.UUID = Field(strict=False)
  kty: str
  crv: str
  x: str
  d: str


class PublicJwk(CamelCaseBaseModel):
  kid: uuid.UUID = Field(strict=False)
  kty: str
  crv: str
  x: str


class PublicVerifyingKeySet(CamelCaseBaseModel):
  keys: list[PublicJwk]


class SignatureComponents(CamelCaseBaseModel):
  recipient_id: str
  webhook_id: str
  signed_at: int
  key_id: uuid.UUID = Field(strict=False)


class InvalidKeyFound(Exception):
  pass


class SignReturnValue(CamelCaseBaseModel):
  webhook_signature_components: str
  webhook_signature: str


class InvalidMethod(Exception):
  pass


class InvalidSigningKey(Exception):
  pass


class VerifyReturnValue(CamelCaseBaseModel):
  webhook_id: str


class PublicVerifyingKeyNotFound(Exception):
  pass


class PublicVerifyingKeyRetrievalFailed(Exception):
  pass


class InvalidSignature(Exception):
  pass


class InvalidPublicVerifyingKey(Exception):
  pass


def generate_secret_signing_key() -> SecretSigningKey:
  key_id = uuid.uuid4()
  signing_key = Ed25519PrivateKey.generate()
  secret_key = _base64_encode(signing_key.private_bytes_raw())
  public_key = _base64_encode(signing_key.public_key().public_bytes_raw())
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
  public_jwks = PublicVerifyingKeySet(keys=[])
  for private_key in secret_signing_keys:
    try:
      public_key = PublicJwk.model_validate(private_key.model_dump())
    except ValueError as err:
      raise InvalidKeyFound() from err
    public_jwks.keys.append(public_key)
  return public_jwks


def sign(
  recipient_id: str,
  webhook_id: str,
  method: str,
  http_body: bytes,
  secret_signing_key: SecretSigningKey,
) -> SignReturnValue:
  if method != "POST":
    raise InvalidMethod()

  key_id = secret_signing_key.kid
  signed_at = seconds_since_unix_epoch()

  signature_components = SignatureComponents(
    recipient_id=recipient_id,
    webhook_id=webhook_id,
    signed_at=signed_at,
    key_id=key_id,
  )

  signature_components_bytes, signature_components_header_value = (
    encode_signature_components_header(signature_components)
  )

  try:
    secret_key_bytes = _base64_decode(secret_signing_key.d)
    if len(secret_key_bytes) != _SECRET_KEY_LENGTH:
      raise InvalidSigningKey()
    public_key_bytes = _base64_decode(secret_signing_key.x)
    if len(public_key_bytes) != _PUBLIC_KEY_LENGTH:
      raise InvalidSigningKey()
    signing_key = Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
    derived_public_key_bytes = signing_key.public_key().public_bytes_raw()
    if derived_public_key_bytes != public_key_bytes:
      raise InvalidSigningKey()
  except ValueError as err:
    raise InvalidSigningKey() from err

  signature_message = construct_signature_message(signature_components_bytes, http_body)

  signature = signing_key.sign(signature_message)
  signature_base64 = _base64_encode(signature)
  signature_header_value = f"{SIGNATURE_VERSION},{signature_base64}"

  return SignReturnValue(
    webhook_signature_components=signature_components_header_value,
    webhook_signature=signature_header_value,
  )


class Verifier:
  def __init__(
    self,
    expected_recipient_id: str,
    signature_ttl_seconds: int,
    public_verifying_key_set_url: str,
  ) -> None:
    self._expected_recipient_id = expected_recipient_id
    self._signature_ttl_seconds = signature_ttl_seconds
    self._public_verifying_key_set_url = public_verifying_key_set_url
    self._public_verifying_key_set = PublicVerifyingKeySet(keys=[])

  async def verify(
    self,
    method: str,
    webhook_signature_components_header: str,
    webhook_signature_header: str,
    http_body: bytes,
  ) -> VerifyReturnValue:
    try:
      return verify(
        method,
        webhook_signature_components_header,
        webhook_signature_header,
        http_body,
        self._expected_recipient_id,
        self._signature_ttl_seconds,
        self._public_verifying_key_set,
      )
    except PublicVerifyingKeyNotFound:
      try:
        await self._refresh_jwks()
      except Exception:  # noqa
        raise PublicVerifyingKeyRetrievalFailed()
      return verify(
        method,
        webhook_signature_components_header,
        webhook_signature_header,
        http_body,
        self._expected_recipient_id,
        self._signature_ttl_seconds,
        self._public_verifying_key_set,
      )

  def verify_sync(
    self,
    method: str,
    webhook_signature_components_header: str,
    webhook_signature_header: str,
    http_body: bytes,
  ) -> VerifyReturnValue:
    try:
      return verify(
        method,
        webhook_signature_components_header,
        webhook_signature_header,
        http_body,
        self._expected_recipient_id,
        self._signature_ttl_seconds,
        self._public_verifying_key_set,
      )
    except PublicVerifyingKeyNotFound:
      try:
        self._refresh_jwks_sync()
      except Exception:  # noqa
        raise PublicVerifyingKeyRetrievalFailed()
      return verify(
        method,
        webhook_signature_components_header,
        webhook_signature_header,
        http_body,
        self._expected_recipient_id,
        self._signature_ttl_seconds,
        self._public_verifying_key_set,
      )

  async def _refresh_jwks(self) -> None:
    async with httpx.AsyncClient() as client:
      response = await client.get(self._public_verifying_key_set_url)
    if response.status_code != 200:
      raise RuntimeError(
        "Failed to retrieve public verifying key set. "
        f"Status code: {response.status_code}"
      )
    self._public_verifying_key_set = PublicVerifyingKeySet.model_validate_json(
      response.content
    )

  def _refresh_jwks_sync(self) -> None:
    with httpx.Client() as client:
      response = client.get(self._public_verifying_key_set_url)
    if response.status_code != 200:
      raise RuntimeError(
        "Failed to retrieve public verifying key set. "
        f"Status code: {response.status_code}"
      )
    self._public_verifying_key_set = PublicVerifyingKeySet.model_validate_json(
      response.content
    )


def verify(
  method: str,
  webhook_signature_components_header: str,
  webhook_signature_header: str,
  http_body: bytes,
  expected_recipient_id: str,
  signature_ttl_seconds: int,
  public_verifying_key_set: PublicVerifyingKeySet,
) -> VerifyReturnValue:
  now = seconds_since_unix_epoch()
  return verify_with_time(
    method,
    webhook_signature_components_header,
    webhook_signature_header,
    http_body,
    expected_recipient_id,
    signature_ttl_seconds,
    public_verifying_key_set,
    now,
  )


def verify_with_time(
  method: str,
  webhook_signature_components_header: str,
  webhook_signature_header: str,
  http_body: bytes,
  expected_recipient_id: str,
  signature_ttl_seconds: int,
  public_verifying_key_set: PublicVerifyingKeySet,
  now: int,
) -> VerifyReturnValue:
  if method != "POST":
    raise InvalidSignature()

  signature_components_encoded = split_versioned_header(
    webhook_signature_components_header
  ).get(SIGNATURE_VERSION)
  if signature_components_encoded is None:
    raise InvalidSignature()
  try:
    signature_components_bytes = _base64_decode(signature_components_encoded)
    signature_components = SignatureComponents.model_validate_json(
      signature_components_bytes
    )
  except ValueError as err:
    raise InvalidSignature() from err

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
    public_key_bytes = _base64_decode(verifying_key_jwk.x)
    if len(public_key_bytes) != _PUBLIC_KEY_LENGTH:
      raise InvalidPublicVerifyingKey()
    verifying_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
  except ValueError as err:
    raise InvalidPublicVerifyingKey() from err

  signature_message = construct_signature_message(signature_components_bytes, http_body)

  signature_encoded = split_versioned_header(webhook_signature_header).get(
    SIGNATURE_VERSION
  )
  if signature_encoded is None:
    raise InvalidSignature()
  try:
    signature_bytes = _base64_decode(signature_encoded)
  except ValueError as err:
    raise InvalidSignature() from err
  if len(signature_bytes) != _SIGNATURE_LENGTH:
    raise InvalidSignature()

  try:
    verifying_key.verify(signature_bytes, signature_message)
  except CrytpographyInvalidSignature as err:
    raise InvalidSignature() from err

  if now > signature_components.signed_at + signature_ttl_seconds:
    raise InvalidSignature()

  if expected_recipient_id != signature_components.recipient_id:
    raise InvalidSignature()

  return VerifyReturnValue(webhook_id=signature_components.webhook_id)


def encode_signature_components_header(
  signature_components: SignatureComponents,
) -> tuple[bytes, str]:
  signature_components_bytes = signature_components.model_dump_json().encode("utf-8")
  signature_components_base64 = _base64_encode(signature_components_bytes)
  signature_components_header_value = (
    f"{SIGNATURE_VERSION},{signature_components_base64}"
  )

  return signature_components_bytes, signature_components_header_value


def construct_signature_message(
  signature_components_bytes: bytes, http_body: bytes
) -> bytes:
  return signature_components_bytes + http_body


def split_versioned_header(header: str) -> dict[str, str]:
  split_headers: dict[str, str] = {}
  for versioned_value in header.split(" "):
    parts = versioned_value.split(",")
    if len(parts) < 2:
      continue
    split_headers[parts[0]] = parts[1]
  return split_headers


def seconds_since_unix_epoch() -> int:
  return int(time.time())


def _base64_encode(value: bytes) -> str:
  return base64.urlsafe_b64encode(value).decode("utf-8")


def _base64_decode(string: str) -> bytes:
  return base64.urlsafe_b64decode(string)
