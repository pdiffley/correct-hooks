use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use correct_hooks::{
  CreatePublicVerifyingKeySetError, PublicVerifyingKeySet, SecretSigningKey, SignWebhookError, SignWebhookValue, VerifyWebhookError, VerifyWebhookValue, test_server::{ApiResponse, CreatePublicVerifyingKeySetRequest, SignWebhookRequest, VerifyWebhookWithTimeRequest},
};
use reqwest::Client;

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
      .send().await.unwrap()
      .json().await.unwrap()
  }

  #[async_backtrace::framed]
  pub async fn generate_secret_signing_key(&self) -> SecretSigningKey {
    self
      .http_client
      .post(format!("http://localhost:{}/generate_secret_signing_key", self.test_server_port))
      .timeout(Duration::from_secs(2))
      .send().await.unwrap()
      .json().await.unwrap()
  }

  #[async_backtrace::framed]
  pub async fn create_public_verifying_key_set(
    &self,
    secret_signing_keys: &[SecretSigningKey],
  ) -> Result<PublicVerifyingKeySet, CreatePublicVerifyingKeySetError> {
    let response: ApiResponse<PublicVerifyingKeySet> = self
      .http_client
      .post(format!("http://localhost:{}/create_public_verifying_key_set", self.test_server_port))
      .timeout(Duration::from_secs(2))
      .json(&CreatePublicVerifyingKeySetRequest {
        keys: secret_signing_keys.iter().cloned().collect(),
      })
      .send().await.unwrap()
      .json().await.unwrap();
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
  pub async fn sign_webhook(
    &self,
    recipient_id: &str,
    webhook_id: &str,
    method: &str,
    http_body: &[u8],
    signing_key: &SecretSigningKey,
  ) -> Result<SignWebhookValue, SignWebhookError> {
    let response: ApiResponse<SignWebhookValue> = self
      .http_client
      .post(format!("http://localhost:{}/sign_webhook", self.test_server_port))
      .timeout(Duration::from_secs(2))
      .json(&SignWebhookRequest {
        recipient_id: recipient_id.to_string(),
        webhook_id: webhook_id.to_string(),
        method: method.to_string(),
        body: URL_SAFE_NO_PAD.encode(http_body),
        signing_key: signing_key.clone(),
      })
      .send().await.unwrap()
      .json().await.unwrap();
    if let Some(error) = response.error {
      let error = match error.as_str() {
        "InvalidMethod" => SignWebhookError::InvalidMethod,
        "InvalidSigningKey" => SignWebhookError::InvalidSigningKey,
        _ => panic!("found unexpected error"),
      };
      return Err(error);
    }
    Ok(response.output.unwrap())
  }

  #[async_backtrace::framed]
  pub async fn verify_webhook_with_time(
    &self,
    method: &str,
    webhook_signature_components_header: &str,
    webhook_signature_header: &str,
    http_body: &[u8],
    expected_recipient_id: &str,
    signature_ttl_seconds: usize,
    public_verifying_key_set: &PublicVerifyingKeySet,
    now: u64,
  ) -> Result<VerifyWebhookValue, VerifyWebhookError> {
    let response: ApiResponse<VerifyWebhookValue> = self
      .http_client
      .post(format!("http://localhost:{}/verify_webhook_with_time", self.test_server_port))
      .timeout(Duration::from_secs(2))
      .json(&VerifyWebhookWithTimeRequest {
        method: method.to_string(),
        webhook_signature_components_header: webhook_signature_components_header.to_string(),
        webhook_signature_header: webhook_signature_header.to_string(),
        body: URL_SAFE_NO_PAD.encode(http_body),
        expected_recipient_id: expected_recipient_id.to_string(),
        signature_ttl_seconds,
        public_verifying_key_set: public_verifying_key_set.clone(),
        now,
      })
      .send().await.unwrap()
      .json().await.unwrap();
    if let Some(error) = response.error {
      let error = match error.as_str() {
        "PublicVerifyingKeyNotFound" => VerifyWebhookError::PublicVerifyingKeyNotFound,
        "InvalidSignature" => VerifyWebhookError::InvalidSignature,
        "InvalidPublicVerifyingKey" => VerifyWebhookError::InvalidPublicVerifyingKey,
        _ => panic!("found unexpected error"),
      };
      return Err(error);
    }
    Ok(response.output.unwrap())
  }
}
