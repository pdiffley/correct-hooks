use std::net::SocketAddr;

use crate::{
  CreatePublicVerifyingKeySetError, PublicVerifyingKeySet, SecretSigningKey, SignWebhookError,
  SignWebhookValue, VerifyWebhookError, VerifyWebhookValue,
  create_public_verifying_key_set, generate_secret_signing_key, sign_webhook,
  verify_webhook_with_time,
};
use axum::http::StatusCode;
use axum::{
  Json, Router,
  routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Clone, Debug)]
struct ServerConfig {
  #[arg(long = "port", env = "RUST_CORRECT_HOOKS_TEST_SERVER_PORT")]
  pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
  pub output: Option<T>,
  pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreatePublicVerifyingKeySetRequest {
  pub keys: Vec<SecretSigningKey>,
}

#[derive(Serialize, Deserialize)]
pub struct SignWebhookRequest {
  pub recipient_id: String,
  pub webhook_id: String,
  pub method: String,
  pub body: String,
  pub signing_key: SecretSigningKey,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyWebhookWithTimeRequest {
  pub method: String,
  pub webhook_signature_components_header: String,
  pub webhook_signature_header: String,
  pub body: String,
  pub expected_recipient_id: String,
  pub signature_ttl_seconds: usize,
  pub public_verifying_key_set: PublicVerifyingKeySet,
  pub now: u64,
}

pub async fn main() {
  let server_config = ServerConfig::parse();
  let port = server_config.port;
  let address: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();

  let router = Router::new()
    .route("/health", get(health))
    .route(
      "/generate_secret_signing_key",
      post(generate_secret_signing_key_endpoint),
    )
    .route(
      "/create_public_verifying_key_set",
      post(create_public_verifying_key_set_endpoint),
    )
    .route("/sign_webhook", post(sign_webhook_endpoint))
    .route(
      "/verify_webhook_with_time",
      post(verify_webhook_with_time_endpoint),
    );

  println!("listening on http://{address}");
  axum_server::bind(address)
    .serve(router.into_make_service())
    .await
    .unwrap();
}

async fn health() -> StatusCode {
  StatusCode::OK
}

async fn generate_secret_signing_key_endpoint() -> Json<SecretSigningKey> {
  Json(generate_secret_signing_key())
}

async fn create_public_verifying_key_set_endpoint(
  Json(req): Json<CreatePublicVerifyingKeySetRequest>,
) -> Json<ApiResponse<PublicVerifyingKeySet>> {
  let result = create_public_verifying_key_set(&req.keys);
  let response = match result {
    Ok(out) => ApiResponse {
      output: Some(out),
      error: None,
    },
    Err(err) => ApiResponse {
      output: None,
      error: Some(
        match err {
          CreatePublicVerifyingKeySetError::InvalidKeyFound => "InvalidKeyFound",
        }
        .to_string(),
      ),
    },
  };
  Json(response)
}

async fn sign_webhook_endpoint(
  Json(req): Json<SignWebhookRequest>,
) -> Json<ApiResponse<SignWebhookValue>> {
  let body = URL_SAFE_NO_PAD.decode(req.body).unwrap();
  let result = sign_webhook(
    &req.recipient_id,
    &req.webhook_id,
    &req.method,
    &body,
    &req.signing_key,
  );
  let response = match result {
    Ok(out) => ApiResponse {
      output: Some(out),
      error: None,
    },
    Err(err) => ApiResponse {
      output: None,
      error: Some(
        match err {
          SignWebhookError::InvalidMethod => "InvalidMethod",
          SignWebhookError::InvalidSigningKey => "InvalidSigningKey",
        }
        .to_string(),
      ),
    },
  };
  Json(response)
}

async fn verify_webhook_with_time_endpoint(
  Json(req): Json<VerifyWebhookWithTimeRequest>,
) -> Json<ApiResponse<VerifyWebhookValue>> {
  let body = URL_SAFE_NO_PAD.decode(req.body).unwrap();
  let result = verify_webhook_with_time(
    &req.method,
    &req.webhook_signature_components_header,
    &req.webhook_signature_header,
    &body,
    &req.expected_recipient_id,
    req.signature_ttl_seconds,
    &req.public_verifying_key_set,
    req.now,
  );
  let response = match result {
    Ok(out) => ApiResponse {
      output: Some(out),
      error: None,
    },
    Err(err) => ApiResponse {
      output: None,
      error: Some(
        match err {
          VerifyWebhookError::PublicVerifyingKeyNotFound => "PublicVerifyingKeyNotFound",
          VerifyWebhookError::InvalidSignature => "InvalidSignature",
          VerifyWebhookError::InvalidPublicVerifyingKey => "InvalidPublicVerifyingKey",
        }
        .to_string(),
      ),
    },
  };
  Json(response)
}
