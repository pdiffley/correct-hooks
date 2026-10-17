use std::time::Duration;

use correct_hooks::{
  CreatePublicVerifyingKeySetError, PublicVerifyingKeySet, SIGNATURE_VERSION, SecretSigningKey,
  SignArgs, SignError, SignatureComponents, SignatureData, VerifiedData, VerifierConfig,
  VerifyArgs, VerifyError, decode_signature_components, encode_base64, split_versioned_header,
};
use reqwest::Client;
use test_server::{
  ApiResponse, CreatePublicVerifyingKeySetRequest, RegisterPublicVerifyingKeySetRequest,
  SignRequest, VerifyWithTimeRequest, VerifyWithTimeWithVerifierRequest,
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
  pub async fn sign(&self, args: SignArgs<'_>) -> Result<SignatureData, SignError> {
    let response: ApiResponse<SignatureData> = self
      .http_client
      .post(format!("http://localhost:{}/sign", self.test_server_port))
      .timeout(Duration::from_secs(2))
      .json(&SignRequest {
        target_url: args.target_url.to_string(),
        webhook_id: args.webhook_id.to_string(),
        recipient_id: args.recipient_id.to_string(),
        method: args.method.to_string(),
        body: encode_base64(args.request_body),
        signing_key: args.secret_signing_key.clone(),
      })
      .send()
      .await
      .unwrap()
      .json()
      .await
      .unwrap();
    if let Some(error) = response.error {
      let error = match error.as_str() {
        "InvalidArgs" => SignError::InvalidArgs,
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
    args: VerifyArgs<'_>,
    recipient_id: Uuid,
    signature_ttl_seconds: u64,
    public_verifying_key_set: &PublicVerifyingKeySet,
    now: u64,
  ) -> Result<VerifiedData, VerifyError> {
    let response: ApiResponse<VerifiedData> = self
      .http_client
      .post(format!(
        "http://localhost:{}/verify_with_time",
        self.test_server_port
      ))
      .timeout(Duration::from_secs(2))
      .json(&VerifyWithTimeRequest {
        recipient_id: recipient_id.to_string(),
        target_url: args.target_url.to_string(),
        method: args.method.to_string(),
        correct_hooks_signature_components: args.correct_hooks_signature_components.to_string(),
        correct_hooks_signature: args.correct_hooks_signature.to_string(),
        body: encode_base64(args.request_body),
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
    public_verifying_key_set: Option<PublicVerifyingKeySet>,
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
    recipient_id: Uuid,
    public_verifying_key_set_id: Uuid,
    signature_ttl_seconds: Option<u64>,
    public_verifying_key_set_ttl_seconds: Option<u64>,
  ) {
    let response = self
      .http_client
      .post(format!(
        "http://localhost:{}/register_new_verifier/{}",
        self.test_server_port, verifier_id
      ))
      .timeout(Duration::from_secs(2))
      .json(&VerifierConfig {
        recipient_id,
        public_verifying_key_set_url: format!(
          "http://localhost:{}/get_public_verifying_key_set/{}",
          self.test_server_port, public_verifying_key_set_id
        ),
        signature_ttl_seconds,
        public_verifying_key_set_ttl_seconds,
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
  pub async fn verify_with_time_with_verifier(
    &self,
    verifier_id: Uuid,
    args: VerifyArgs<'_>,
    now: u64,
  ) -> Result<VerifiedData, VerifyError> {
    let response: ApiResponse<VerifiedData> = self
      .http_client
      .post(format!(
        "http://localhost:{}/verify_with_time_with_verifier/{}",
        self.test_server_port, verifier_id
      ))
      .timeout(Duration::from_secs(60))
      .json(&VerifyWithTimeWithVerifierRequest {
        target_url: args.target_url.to_string(),
        method: args.method.to_string(),
        correct_hooks_signature_components: args.correct_hooks_signature_components.to_string(),
        correct_hooks_signature: args.correct_hooks_signature.to_string(),
        body: encode_base64(args.request_body),
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
}

fn convert_verifying_error(error: &str) -> VerifyError {
  match error {
    "PublicVerifyingKeyNotFound" => VerifyError::PublicVerifyingKeyNotFound,
    "InvalidSignature" => VerifyError::InvalidSignature,
    "InvalidPublicVerifyingKey" => VerifyError::InvalidPublicVerifyingKey,
    _ => panic!("found unexpected error"),
  }
}

pub fn decode_signature_components_test(
  correct_hooks_signature_components: &str,
) -> SignatureComponents {
  let signature_components_encoded = split_versioned_header(correct_hooks_signature_components)
    .get(SIGNATURE_VERSION)
    .unwrap()
    .clone();
  let signature_components = decode_signature_components(&signature_components_encoded).unwrap();
  signature_components
}
