use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use correct_hooks::{
  CreatePublicVerifyingKeySetError, PublicVerifyingKeySet, SIGNATURE_VERSION, SecretSigningKey,
  SignError, SignReturnValue, SignatureComponents, VerifyError, VerifyReturnValue,
  split_versioned_header,
};
use reqwest::Client;
use test_server::{
  ApiResponse, CreatePublicVerifyingKeySetRequest, NewVerifierRequest,
  RegisterPublicVerifyingKeySetRequest, SignRequest, VerifyWithTimeRequest,
  VerifyWithVerifierRequest,
};
use uuid::Uuid;

pub struct CorrectHooksTestClient {
  test_server_port: u16,
  http_client: Client,
}

impl CorrectHooksTestClient {
  pub fn new(test_server_port: u16) -> Self {
    Self {
      test_server_port,
      http_client: Client::new(),
    }
  }

  #[async_backtrace::framed]
  pub async fn health(&self) -> String {
    self
      .http_client
      .get(format!("http://localhost:{}/health", self.test_server_port))
      .timeout(Duration::from_secs(2))
      .send()
      .await
      .unwrap()
      .json()
      .await
      .unwrap()
  }

  #[async_backtrace::framed]
  pub async fn generate_secret_signing_key(&self) -> SecretSigningKey {
    self
      .http_client
      .post(format!(
        "http://localhost:{}/generate_secret_signing_key",
        self.test_server_port
      ))
      .timeout(Duration::from_secs(2))
      .send()
      .await
      .unwrap()
      .json()
      .await
      .unwrap()
  }

  #[async_backtrace::framed]
  pub async fn create_public_verifying_key_set(
    &self,
    secret_signing_keys: &[SecretSigningKey],
  ) -> Result<PublicVerifyingKeySet, CreatePublicVerifyingKeySetError> {
    let response: ApiResponse<PublicVerifyingKeySet> = self
      .http_client
      .post(format!(
        "http://localhost:{}/create_public_verifying_key_set",
        self.test_server_port
      ))
      .timeout(Duration::from_secs(2))
      .json(&CreatePublicVerifyingKeySetRequest {
        keys: secret_signing_keys.iter().cloned().collect(),
      })
      .send()
      .await
      .unwrap()
      .json()
      .await
      .unwrap();
    if let Some(error) = response.error {
      let error = match error.as_str() {
        "InvalidKeyFound" => CreatePublicVerifyingKeySetError::InvalidKeyFound,
        _ => panic!("found unexpected error"),
      };
      return Err(error);
    }
    Ok(response.output.unwrap())
  }

  #[async_backtrace::framed]
  pub async fn sign(
    &self,
    recipient_id: &str,
    webhook_id: &str,
    method: &str,
    http_body: &[u8],
    signing_key: &SecretSigningKey,
  ) -> Result<SignReturnValue, SignError> {
    let response: ApiResponse<SignReturnValue> = self
      .http_client
      .post(format!("http://localhost:{}/sign", self.test_server_port))
      .timeout(Duration::from_secs(2))
      .json(&SignRequest {
        recipient_id: recipient_id.to_string(),
        webhook_id: webhook_id.to_string(),
        method: method.to_string(),
        body: URL_SAFE.encode(http_body),
        signing_key: signing_key.clone(),
      })
      .send()
      .await
      .unwrap()
      .json()
      .await
      .unwrap();
    if let Some(error) = response.error {
      let error = match error.as_str() {
        "InvalidMethod" => SignError::InvalidMethod,
        "InvalidSigningKey" => SignError::InvalidSigningKey,
        _ => panic!("found unexpected error"),
      };
      return Err(error);
    }
    Ok(response.output.unwrap())
  }

  #[async_backtrace::framed]
  pub async fn verify_with_time(
    &self,
    method: &str,
    webhook_signature_components_header: &str,
    webhook_signature_header: &str,
    http_body: &[u8],
    expected_recipient_id: &str,
    signature_ttl_seconds: usize,
    public_verifying_key_set: &PublicVerifyingKeySet,
    now: u64,
  ) -> Result<VerifyReturnValue, VerifyError> {
    let response: ApiResponse<VerifyReturnValue> = self
      .http_client
      .post(format!(
        "http://localhost:{}/verify_with_time",
        self.test_server_port
      ))
      .timeout(Duration::from_secs(2))
      .json(&VerifyWithTimeRequest {
        method: method.to_string(),
        webhook_signature_components_header: webhook_signature_components_header.to_string(),
        webhook_signature_header: webhook_signature_header.to_string(),
        body: URL_SAFE.encode(http_body),
        expected_recipient_id: expected_recipient_id.to_string(),
        signature_ttl_seconds,
        public_verifying_key_set: public_verifying_key_set.clone(),
        now,
      })
      .send()
      .await
      .unwrap()
      .json()
      .await
      .unwrap();
    if let Some(error) = response.error {
      return Err(convert_verifying_error(error.as_str()));
    }
    Ok(response.output.unwrap())
  }
  #[async_backtrace::framed]
  pub async fn set_public_verifying_key_set(
    &self,
    public_verifying_key_set_id: Uuid,
    public_verifying_key_set: &PublicVerifyingKeySet,
  ) {
    let response = self
      .http_client
      .post(format!(
        "http://localhost:{}/register_public_verifying_key_set/{}",
        self.test_server_port, public_verifying_key_set_id
      ))
      .timeout(Duration::from_secs(2))
      .json(&RegisterPublicVerifyingKeySetRequest {
        public_verifying_key_set: public_verifying_key_set.clone(),
      })
      .send()
      .await
      .unwrap();
    assert!(
      response.status().is_success(),
      "register_public_verifying_key_set failed: {}",
      response.status()
    );
  }

  #[async_backtrace::framed]
  pub async fn register_new_verifier(
    &self,
    verifier_id: Uuid,
    expected_recipient_id: &str,
    signature_ttl_seconds: usize,
    public_verifying_key_set_id: Uuid,
  ) {
    let response = self
      .http_client
      .post(format!(
        "http://localhost:{}/register_new_verifier/{}",
        self.test_server_port, verifier_id
      ))
      .timeout(Duration::from_secs(2))
      .json(&NewVerifierRequest {
        expected_recipient_id: expected_recipient_id.to_string(),
        signature_ttl_seconds,
        public_verifying_key_set_url: format!(
          "http://localhost:{}/get_public_verifying_key_set/{}",
          self.test_server_port, public_verifying_key_set_id
        ),
      })
      .send()
      .await
      .unwrap();
    assert!(
      response.status().is_success(),
      "register_new_verifier failed: {}",
      response.status()
    );
  }

  #[async_backtrace::framed]
  pub async fn verify_with_verifier(
    &self,
    verifier_id: Uuid,
    method: &str,
    webhook_signature_components_header: &str,
    webhook_signature_header: &str,
    http_body: &[u8],
  ) -> Result<VerifyReturnValue, VerifyError> {
    let response: ApiResponse<VerifyReturnValue> = self
      .http_client
      .post(format!(
        "http://localhost:{}/verify_with_verifier/{}",
        self.test_server_port, verifier_id
      ))
      .timeout(Duration::from_secs(60))
      .json(&VerifyWithVerifierRequest {
        method: method.to_string(),
        webhook_signature_components_header: webhook_signature_components_header.to_string(),
        webhook_signature_header: webhook_signature_header.to_string(),
        body: URL_SAFE.encode(http_body),
      })
      .send()
      .await
      .unwrap()
      .json()
      .await
      .unwrap();
    if let Some(error) = response.error {
      return Err(convert_verifying_error(error.as_str()));
    }
    Ok(response.output.unwrap())
  }
}

fn convert_verifying_error(error: &str) -> VerifyError {
  match error {
    "PublicVerifyingKeyNotFound" => VerifyError::PublicVerifyingKeyNotFound,
    "InvalidSignature" => VerifyError::InvalidSignature,
    "InvalidPublicVerifyingKey" => VerifyError::InvalidPublicVerifyingKey,
    _ => panic!("found unexpected error"),
  }
}

pub fn decode_signature_components(
  webhook_signature_components_header: &str,
) -> SignatureComponents {
  let signature_components_encoded = split_versioned_header(webhook_signature_components_header)
    .get(SIGNATURE_VERSION)
    .unwrap()
    .clone();
  let signature_components_bytes = URL_SAFE.decode(&signature_components_encoded).unwrap();
  let signature_components =
    serde_json::from_slice::<SignatureComponents>(&signature_components_bytes).unwrap();
  signature_components
}

// Todo: Write test script
