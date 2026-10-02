use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{
    Json, Router,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use clap::Parser;
use correct_hooks::{
    CreatePublicVerifyingKeySetError, PublicVerifyingKeySet, SecretSigningKey, SignError,
    SignReturnValue, Verifier, VerifyError, VerifyReturnValue, create_public_verifying_key_set,
    generate_secret_signing_key, sign, verify_with_time,
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
    pub recipient_id: String,
    pub webhook_id: String,
    pub method: String,
    pub body: String,
    pub signing_key: SecretSigningKey,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyWithTimeRequest {
    pub method: String,
    pub webhook_signature_components_header: String,
    pub webhook_signature_header: String,
    pub body: String,
    pub expected_recipient_id: String,
    pub signature_ttl_seconds: usize,
    pub public_verifying_key_set: PublicVerifyingKeySet,
    pub now: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPublicVerifyingKeySetRequest {
    pub public_verifying_key_set: PublicVerifyingKeySet,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewVerifierRequest {
    pub expected_recipient_id: String,
    pub signature_ttl_seconds: usize,
    pub public_verifying_key_set_url: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyWithVerifierRequest {
    pub method: String,
    pub webhook_signature_components_header: String,
    pub webhook_signature_header: String,
    pub body: String,
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
        .route("/verify_with_verifier/{id}", post(verify_with_verifier))
        .with_state(server_state);

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

async fn sign_endpoint(Json(request): Json<SignRequest>) -> Json<ApiResponse<SignReturnValue>> {
    let body = URL_SAFE.decode(request.body).unwrap();
    let result = sign(
        &request.recipient_id,
        &request.webhook_id,
        &request.method,
        &body,
        &request.signing_key,
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
                    SignError::InvalidMethod => "InvalidMethod",
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
) -> Json<ApiResponse<VerifyReturnValue>> {
    let body = URL_SAFE.decode(request.body).unwrap();
    let result = verify_with_time(
        &request.method,
        &request.webhook_signature_components_header,
        &request.webhook_signature_header,
        &body,
        &request.expected_recipient_id,
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
                    VerifyError::PublicVerifyingKeyRetrievalFailed => {
                        "PublicVerifyingKeyRetrievalFailed"
                    }
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
    server_state
        .public_verifying_key_sets
        .lock()
        .await
        .insert(id, request.public_verifying_key_set);
    StatusCode::OK
}

async fn get_public_verifying_key_set(
    State(server_state): State<Arc<ServerState>>,
    Path(id): Path<Uuid>,
) -> Json<PublicVerifyingKeySet> {
    Json(
        server_state
            .public_verifying_key_sets
            .lock()
            .await
            .get(&id)
            .unwrap()
            .clone(),
    )
}

async fn register_new_verifier(
    State(server_state): State<Arc<ServerState>>,
    Path(id): Path<Uuid>,
    Json(request): Json<NewVerifierRequest>,
) -> StatusCode {
    let NewVerifierRequest {
        expected_recipient_id,
        signature_ttl_seconds,
        public_verifying_key_set_url,
    } = request;
    let verifier = Verifier::new(
        expected_recipient_id,
        signature_ttl_seconds,
        public_verifying_key_set_url,
    )
    .unwrap();
    server_state.verifiers.lock().await.insert(id, verifier);
    StatusCode::OK
}
#[axum::debug_handler]
async fn verify_with_verifier(
    State(server_state): State<Arc<ServerState>>,
    Path(id): Path<Uuid>,
    Json(request): Json<VerifyWithVerifierRequest>,
) -> Json<ApiResponse<VerifyReturnValue>> {
    let body = URL_SAFE.decode(request.body).unwrap();
    let mut verifiers_guard = server_state.verifiers.lock().await;
    let verifier = verifiers_guard.get_mut(&id).unwrap();
    let result = verifier
        .verify(
            &request.method,
            &request.webhook_signature_components_header,
            &request.webhook_signature_header,
            &body,
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
                    VerifyError::PublicVerifyingKeyRetrievalFailed => {
                        "PublicVerifyingKeyRetrievalFailed"
                    }
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
