from __future__ import annotations

import argparse
import asyncio
import os
import uuid
from typing import Generic, TypeVar

import uvicorn
from correct_hooks import (
  CamelCaseBaseModel,
  InvalidKeyFound,
  InvalidArgs,
  InvalidPublicVerifyingKey,
  InvalidSignature,
  InvalidSigningKey,
  PublicVerifyingKeyNotFound,
  PublicVerifyingKeyRetrievalFailed,
  PublicVerifyingKeySet,
  SecretSigningKey,
  SignArgs,
  SignatureData,
  VerifiedData,
  Verifier,
  VerifyArgs,
  create_public_verifying_key_set,
  decode_base64,
  generate_secret_signing_key,
  sign,
  verify_with_time,
)
from fastapi import FastAPI, HTTPException
from pydantic import AnyUrl, BaseModel

T = TypeVar("T")

parser = argparse.ArgumentParser()
env_port = os.environ.get("PYTHON_CORRECT_HOOKS_TEST_SERVER_PORT")
parser.add_argument(
  "--port",
  type=int,
  default=int(env_port) if env_port else None,
  required=env_port is None,
)
parser.add_argument("--mode", type=str, required=True)
parsed_args = parser.parse_args()
PORT = parsed_args.port
if not (parsed_args.mode == "async" or parsed_args.mode == "sync"):
  raise Exception("Missing async/sync mode commandline arg")  # noqa
ASYNC_ENABLED = parsed_args.mode == "async"


class ApiResponse(BaseModel, Generic[T]):
  output: T | None
  error: str | None


class CreatePublicVerifyingKeySetRequest(BaseModel):
  keys: list[SecretSigningKey]


class SignRequest(CamelCaseBaseModel):
  target_url: str
  webhook_id: str
  recipient_id: str
  method: str
  body: str
  signing_key: SecretSigningKey


class VerifyWithTimeRequest(CamelCaseBaseModel):
  recipient_id: str
  target_url: str
  method: str
  correct_hooks_signature_components: str
  correct_hooks_signature: str
  body: str
  signature_ttl_seconds: int
  public_verifying_key_set: PublicVerifyingKeySet
  now: int


class RegisterPublicVerifyingKeySetRequest(CamelCaseBaseModel):
  public_verifying_key_set: PublicVerifyingKeySet | None


class VerifierConfig(CamelCaseBaseModel):
  recipient_id: str
  public_verifying_key_set_url: str
  signature_ttl_seconds: int | None
  public_verifying_key_set_ttl_seconds: int | None


class VerifyWithTimeWithVerifierRequest(CamelCaseBaseModel):
  target_url: str
  method: str
  correct_hooks_signature_components: str
  correct_hooks_signature: str
  body: str
  now: int


app = FastAPI()
public_verifying_key_sets: dict[uuid.UUID, PublicVerifyingKeySet] = {}
verifiers: dict[uuid.UUID, Verifier] = {}


@app.get("/health")
async def health() -> None:
  return None


@app.post("/generate_secret_signing_key")
async def generate_secret_signing_key_endpoint() -> SecretSigningKey:
  return generate_secret_signing_key()


@app.post("/create_public_verifying_key_set")
async def create_public_verifying_key_set_endpoint(
  request: CreatePublicVerifyingKeySetRequest,
) -> ApiResponse[PublicVerifyingKeySet]:
  try:
    result = create_public_verifying_key_set(secret_signing_keys=request.keys)
    return ApiResponse(
      output=result,
      error=None,
    )
  except InvalidKeyFound as err:
    return ApiResponse(output=None, error=type(err).__name__)


@app.post("/sign")
async def sign_endpoint(request: SignRequest) -> ApiResponse[SignatureData]:
  body = decode_base64(base64_string=request.body)
  try:
    result = sign(SignArgs(
      webhook_id=uuid.UUID(request.webhook_id),
      recipient_id=uuid.UUID(request.recipient_id),
      target_url=AnyUrl(request.target_url),
      method=request.method,
      request_body=body,
      secret_signing_key=request.signing_key,
    ))
    return ApiResponse(
      output=result,
      error=None,
    )
  except (InvalidArgs, InvalidSigningKey) as err:
    return ApiResponse(output=None, error=type(err).__name__)


@app.post("/verify_with_time")
async def verify_with_time_endpoint(
  request: VerifyWithTimeRequest,
) -> ApiResponse[VerifiedData]:
  body = decode_base64(base64_string=request.body)
  try:
    result = verify_with_time(
      args=VerifyArgs(
        target_url=AnyUrl(request.target_url),
        method=request.method,
        correct_hooks_signature_components=request.correct_hooks_signature_components,
        correct_hooks_signature=request.correct_hooks_signature,
        request_body=body,
      ),
      recipient_id=uuid.UUID(request.recipient_id),
      signature_ttl_seconds=request.signature_ttl_seconds,
      public_verifying_key_set=request.public_verifying_key_set,
      now=request.now,
    )
    return ApiResponse(
      output=result,
      error=None,
    )
  except (
    PublicVerifyingKeyNotFound,
    PublicVerifyingKeyRetrievalFailed,
    InvalidSignature,
    InvalidPublicVerifyingKey,
  ) as err:
    return ApiResponse(output=None, error=type(err).__name__)


@app.post("/register_public_verifying_key_set/{id}")
async def register_public_verifying_key_set(
  id: uuid.UUID, request: RegisterPublicVerifyingKeySetRequest
) -> None:
  if request.public_verifying_key_set is not None:
    public_verifying_key_sets[id] = request.public_verifying_key_set
  else:
    public_verifying_key_sets.pop(id, None)


@app.get("/get_public_verifying_key_set/{id}")
async def get_public_verifying_key_set(id: uuid.UUID) -> PublicVerifyingKeySet:
  key_set = public_verifying_key_sets.get(id)
  if key_set is not None:
    return public_verifying_key_sets[id]
  else:
    raise HTTPException(status_code=404)


@app.post("/register_new_verifier/{id}")
async def register_new_verifier(id: uuid.UUID, request: VerifierConfig) -> None:
  verifiers[id] = Verifier(
    recipient_id=uuid.UUID(request.recipient_id),
    public_verifying_key_set_url=request.public_verifying_key_set_url,
    signature_ttl_seconds=request.signature_ttl_seconds,
    public_verifying_key_set_ttl_seconds=request.public_verifying_key_set_ttl_seconds,
  )


@app.post("/verify_with_time_with_verifier/{id}")
async def verify_with_time_with_verifier(
  id: uuid.UUID, request: VerifyWithTimeWithVerifierRequest
) -> ApiResponse[VerifiedData]:
  body = decode_base64(base64_string=request.body)
  try:
    if ASYNC_ENABLED:
      result = await verifiers[id].verify_with_time(
        args=VerifyArgs(
          target_url=AnyUrl(request.target_url),
          method=request.method,
          correct_hooks_signature_components=request.correct_hooks_signature_components,
          correct_hooks_signature=request.correct_hooks_signature,
          request_body=body,
        ),
        now=request.now,
      )
    else:
      result = await asyncio.to_thread(
        verifiers[id].verify_with_time_sync,
        args=VerifyArgs(
          target_url=AnyUrl(request.target_url),
          method=request.method,
          correct_hooks_signature_components=request.correct_hooks_signature_components,
          correct_hooks_signature=request.correct_hooks_signature,
          request_body=body,
        ),
        now=request.now,
      )

    return ApiResponse(
      output=result,
      error=None,
    )
  except (
    PublicVerifyingKeyNotFound,
    PublicVerifyingKeyRetrievalFailed,
    InvalidSignature,
    InvalidPublicVerifyingKey,
  ) as err:
    return ApiResponse(output=None, error=type(err).__name__)


def main() -> None:
  uvicorn.run(app, host="0.0.0.0", port=PORT)


main()
