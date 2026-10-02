from __future__ import annotations

import argparse
import base64
import os
import uuid
from typing import Generic, TypeVar

import uvicorn
from correct_hooks import (
  CamelCaseBaseModel,
  InvalidKeyFound,
  InvalidMethod,
  InvalidPublicVerifyingKey,
  InvalidSignature,
  InvalidSigningKey,
  PublicVerifyingKeyNotFound,
  PublicVerifyingKeyRetrievalFailed,
  PublicVerifyingKeySet,
  SecretSigningKey,
  SignReturnValue,
  Verifier,
  VerifyReturnValue,
  create_public_verifying_key_set,
  generate_secret_signing_key,
  sign,
  verify_with_time,
)
from fastapi import FastAPI
from pydantic import BaseModel

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
  output: T | None
  error: str | None


class CreatePublicVerifyingKeySetRequest(BaseModel):
  keys: list[SecretSigningKey]


class SignRequest(CamelCaseBaseModel):
  recipient_id: str
  webhook_id: str
  method: str
  body: str
  signing_key: SecretSigningKey


class VerifyWithTimeRequest(CamelCaseBaseModel):
  method: str
  webhook_signature_components_header: str
  webhook_signature_header: str
  body: str
  expected_recipient_id: str
  signature_ttl_seconds: int
  public_verifying_key_set: PublicVerifyingKeySet
  now: int


class RegisterPublicVerifyingKeySetRequest(CamelCaseBaseModel):
  public_verifying_key_set: PublicVerifyingKeySet


class NewVerifierRequest(CamelCaseBaseModel):
  expected_recipient_id: str
  signature_ttl_seconds: int
  public_verifying_key_set_url: str


class VerifyWithVerifierRequest(CamelCaseBaseModel):
  method: str
  webhook_signature_components_header: str
  webhook_signature_header: str
  body: str


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
    result = create_public_verifying_key_set(request.keys)
    return ApiResponse(
      output=result,
      error=None,
    )
  except InvalidKeyFound as err:
    return ApiResponse(output=None, error=type(err).__name__)


@app.post("/sign")
async def sign_endpoint(request: SignRequest) -> ApiResponse[SignReturnValue]:
  body = base64.urlsafe_b64decode(request.body)
  try:
    result = sign(
      request.recipient_id,
      request.webhook_id,
      request.method,
      body,
      request.signing_key,
    )
    return ApiResponse(
      output=result,
      error=None,
    )
  except (InvalidMethod, InvalidSigningKey) as err:
    return ApiResponse(output=None, error=type(err).__name__)


@app.post("/verify_with_time")
async def verify_with_time_endpoint(
  request: VerifyWithTimeRequest,
) -> ApiResponse[VerifyReturnValue]:
  body = base64.urlsafe_b64decode(request.body)
  try:
    result = verify_with_time(
      request.method,
      request.webhook_signature_components_header,
      request.webhook_signature_header,
      body,
      request.expected_recipient_id,
      request.signature_ttl_seconds,
      request.public_verifying_key_set,
      request.now,
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
  public_verifying_key_sets[id] = request.public_verifying_key_set


@app.get("/get_public_verifying_key_set/{id}")
async def get_public_verifying_key_set(id: uuid.UUID) -> PublicVerifyingKeySet:
  return public_verifying_key_sets[id]


@app.post("/register_new_verifier/{id}")
async def register_new_verifier(id: uuid.UUID, request: NewVerifierRequest) -> None:
  verifiers[id] = Verifier(
    request.expected_recipient_id,
    request.signature_ttl_seconds,
    request.public_verifying_key_set_url,
  )


@app.post("/verify_with_verifier/{id}")
async def verify_with_verifier(
  id: uuid.UUID, request: VerifyWithVerifierRequest
) -> ApiResponse[VerifyReturnValue]:
  body = base64.urlsafe_b64decode(request.body)
  try:
    result = await verifiers[id].verify(
      request.method,
      request.webhook_signature_components_header,
      request.webhook_signature_header,
      body,
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
  parser = argparse.ArgumentParser()
  env_port = os.environ.get("PYTHON_CORRECT_HOOKS_TEST_SERVER_PORT")
  parser.add_argument(
    "--port",
    type=int,
    default=int(env_port) if env_port else None,
    required=env_port is None,
  )
  port: int = parser.parse_args().port

  uvicorn.run(app, host="0.0.0.0", port=port)


main()
