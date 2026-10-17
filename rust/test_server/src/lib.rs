use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{
  Json, Router,
  routing::{get, post},
};
use clap::Parser;
use correct_hooks::{
  CreatePublicVerifyingKeySetError, PublicVerifyingKeySet, SecretSigningKey, SignArgs, SignError,
  SignatureData, VerifiedData, Verifier, VerifierConfig, VerifyArgs, VerifyError,
  create_public_verifying_key_set, decode_base64, generate_secret_signing_key, sign,
  verify_with_time,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Parser, Clone, Debug)]
struct ServerConfig {
  #[arg(long = "port", env = "RUST_CORRECT_HOOKS_TEST_SERVER_PORT")]
  pub port: u16,
}

pub struct ServerState {
  pub public_verifying_key_sets: Mutex<HashMap<Uuid, PublicVerifyingKeySet>>,
  pub verifiers: Mutex<HashMap<Uuid, Verifier>>,
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
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
  pub target_url: String,
  pub webhook_id: String,
  pub recipient_id: String,
  pub method: String,
  pub body: String,
  pub signing_key: SecretSigningKey,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyWithTimeRequest {
  pub recipient_id: String,
  pub target_url: String,
  pub method: String,
  pub correct_hooks_signature_components: String,
  pub correct_hooks_signature: String,
  pub body: String,
  pub signature_ttl_seconds: u64,
  pub public_verifying_key_set: PublicVerifyingKeySet,
  pub now: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPublicVerifyingKeySetRequest {
  pub public_verifying_key_set: Option<PublicVerifyingKeySet>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyWithTimeWithVerifierRequest {
  pub target_url: String,
  pub method: String,
  pub correct_hooks_signature_components: String,
  pub correct_hooks_signature: String,
  pub body: String,
  pub now: u64,
}

pub async fn main() {
  let server_config = ServerConfig::parse();
  let port = server_config.port;
  let address: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();

  let server_state = Arc::new(ServerState {
    public_verifying_key_sets: Mutex::new(HashMap::new()),
    verifiers: Mutex::new(HashMap::new()),
  });

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
    .route("/sign", post(sign_endpoint))
    .route("/verify_with_time", post(verify_with_time_endpoint))
    .route(
      "/register_public_verifying_key_set/{id}",
      post(register_public_verifying_key_set),
    )
    .route(
      "/get_public_verifying_key_set/{id}",
      get(get_public_verifying_key_set),
    )
    .route("/register_new_verifier/{id}", post(register_new_verifier))
    .route(
      "/verify_with_time_with_verifier/{id}",
      post(verify_with_time_with_verifier),
    )
    .with_state(server_state);

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
  Json(request): Json<CreatePublicVerifyingKeySetRequest>,
) -> Json<ApiResponse<PublicVerifyingKeySet>> {
  let result = create_public_verifying_key_set(&request.keys);
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
          _ => panic!("Encountered unexpected error"),
        }
        .to_string(),
      ),
    },
  };
  Json(response)
}

async fn sign_endpoint(Json(request): Json<SignRequest>) -> Json<ApiResponse<SignatureData>> {
  let body = decode_base64(&request.body).unwrap();
  let result = sign(SignArgs {
    target_url: &request.target_url.parse().unwrap(),
    webhook_id: request.webhook_id.parse().unwrap(),
    recipient_id: request.recipient_id.parse().unwrap(),
    method: &request.method,
    request_body: &body,
    secret_signing_key: &request.signing_key,
  });
  let response = match result {
    Ok(out) => ApiResponse {
      output: Some(out),
      error: None,
    },
    Err(err) => ApiResponse {
      output: None,
      error: Some(
        match err {
          SignError::InvalidArgs => "InvalidArgs",
          SignError::InvalidSigningKey => "InvalidSigningKey",
          _ => panic!("Encountered unexpected error"),
        }
        .to_string(),
      ),
    },
  };
  Json(response)
}

async fn verify_with_time_endpoint(
  Json(request): Json<VerifyWithTimeRequest>,
) -> Json<ApiResponse<VerifiedData>> {
  let body = decode_base64(&request.body).unwrap();
  let result = verify_with_time(
    VerifyArgs {
      target_url: &request.target_url.parse().unwrap(),
      method: &request.method,
      correct_hooks_signature_components: &request.correct_hooks_signature_components,
      correct_hooks_signature: &request.correct_hooks_signature,
      request_body: &body,
    },
    request.recipient_id.parse().unwrap(),
    request.signature_ttl_seconds,
    &request.public_verifying_key_set,
    request.now,
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
          VerifyError::PublicVerifyingKeyNotFound => "PublicVerifyingKeyNotFound",
          VerifyError::PublicVerifyingKeyRetrievalFailed => "PublicVerifyingKeyRetrievalFailed",
          VerifyError::InvalidSignature => "InvalidSignature",
          VerifyError::InvalidPublicVerifyingKey => "InvalidPublicVerifyingKey",
          _ => panic!("Encountered unexpected error"),
        }
        .to_string(),
      ),
    },
  };
  Json(response)
}

async fn register_public_verifying_key_set(
  State(server_state): State<Arc<ServerState>>,
  Path(id): Path<Uuid>,
  Json(request): Json<RegisterPublicVerifyingKeySetRequest>,
) -> StatusCode {
  if let Some(public_verifying_key_set) = request.public_verifying_key_set {
    server_state
      .public_verifying_key_sets
      .lock()
      .await
      .insert(id, public_verifying_key_set);
  } else {
    server_state
      .public_verifying_key_sets
      .lock()
      .await
      .remove(&id);
  }
  StatusCode::OK
}

async fn get_public_verifying_key_set(
  State(server_state): State<Arc<ServerState>>,
  Path(id): Path<Uuid>,
) -> Result<Json<PublicVerifyingKeySet>, StatusCode> {
  if let Some(public_verifying_key_set) =
    server_state.public_verifying_key_sets.lock().await.get(&id)
  {
    return Ok(Json(public_verifying_key_set.clone()));
  } else {
    Err(StatusCode::NOT_FOUND)
  }
}

async fn register_new_verifier(
  State(server_state): State<Arc<ServerState>>,
  Path(id): Path<Uuid>,
  Json(request): Json<VerifierConfig>,
) -> StatusCode {
  let verifier = Verifier::new(request);
  server_state.verifiers.lock().await.insert(id, verifier);
  StatusCode::OK
}
#[axum::debug_handler]
async fn verify_with_time_with_verifier(
  State(server_state): State<Arc<ServerState>>,
  Path(id): Path<Uuid>,
  Json(request): Json<VerifyWithTimeWithVerifierRequest>,
) -> Json<ApiResponse<VerifiedData>> {
  let body = decode_base64(&request.body).unwrap();
  let mut verifiers_guard = server_state.verifiers.lock().await;
  let verifier = verifiers_guard.get_mut(&id).unwrap();
  let result = verifier
    .verify_with_time(
      VerifyArgs {
        target_url: &request.target_url.parse().unwrap(),
        method: &request.method,
        correct_hooks_signature_components: &request.correct_hooks_signature_components,
        correct_hooks_signature: &request.correct_hooks_signature,
        request_body: &body,
      },
      request.now,
    )
    .await;
  let response = match result {
    Ok(out) => ApiResponse {
      output: Some(out),
      error: None,
    },
    Err(err) => ApiResponse {
      output: None,
      error: Some(
        match err {
          VerifyError::PublicVerifyingKeyNotFound => "PublicVerifyingKeyNotFound",
          VerifyError::PublicVerifyingKeyRetrievalFailed => "PublicVerifyingKeyRetrievalFailed",
          VerifyError::InvalidSignature => "InvalidSignature",
          VerifyError::InvalidPublicVerifyingKey => "InvalidPublicVerifyingKey",
          _ => panic!("Encountered unexpected error"),
        }
        .to_string(),
      ),
    },
  };
  Json(response)
}
