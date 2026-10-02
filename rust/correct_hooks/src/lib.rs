use std::{
  collections::HashMap,
  time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use ed25519_dalek::{
  KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, Signature, Signer, SigningKey, VerifyingKey,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SIGNATURE_VERSION: &'static str = "v1";

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretSigningKey {
  kid: Uuid,
  kty: String,
  crv: String,
  x: String,
  d: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct PublicJwk {
  kid: Uuid,
  kty: String,
  crv: String,
  x: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicVerifyingKeySet {
  keys: Vec<PublicJwk>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureComponents {
  pub recipient_id: String,
  pub webhook_id: String,
  pub signed_at: u64,
  pub key_id: Uuid,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum CreatePublicVerifyingKeySetError {
  InvalidKeyFound,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignReturnValue {
  pub webhook_signature_components: String,
  pub webhook_signature: String,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SignError {
  InvalidMethod,
  InvalidSigningKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReturnValue {
  pub webhook_id: String,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum VerifyError {
  PublicVerifyingKeyNotFound,
  PublicVerifyingKeyRetrievalFailed,
  InvalidSignature,
  InvalidPublicVerifyingKey,
}

pub fn generate_secret_signing_key() -> SecretSigningKey {
  let key_id = Uuid::new_v4();
  let signing_key: SigningKey = SigningKey::generate(&mut rand::rng());
  let secret_key = URL_SAFE.encode(signing_key.as_bytes());
  let public_key = URL_SAFE.encode(signing_key.verifying_key().as_bytes());
  let jwk = SecretSigningKey {
    kid: key_id,
    kty: "OKP".to_string(),
    crv: "Ed25519".to_string(),
    x: public_key,
    d: secret_key,
  };

  jwk
}

pub fn create_public_verifying_key_set(
  secret_signing_keys: &[SecretSigningKey],
) -> Result<PublicVerifyingKeySet, CreatePublicVerifyingKeySetError> {
  let mut public_jwks = PublicVerifyingKeySet { keys: vec![] };
  for private_key in secret_signing_keys {
    let public_key: PublicJwk = serde_json::from_slice(
      &serde_json::to_vec(&private_key).expect("Internal CorrectHooks error"),
    )
    .map_err(|_| CreatePublicVerifyingKeySetError::InvalidKeyFound)?;
    public_jwks.keys.push(public_key);
  }
  Ok(public_jwks)
}

pub fn sign(
  recipient_id: &str,
  webhook_id: &str,
  method: &str,
  http_body: &[u8],
  secret_signing_key: &SecretSigningKey,
) -> Result<SignReturnValue, SignError> {
  if method != "POST" {
    return Err(SignError::InvalidMethod);
  }

  let key_id = secret_signing_key.kid;
  let signed_at = seconds_since_unix_epoch();

  let signature_components = SignatureComponents {
    recipient_id: recipient_id.to_string(),
    webhook_id: webhook_id.to_string(),
    signed_at,
    key_id,
  };

  let (signature_components_bytes, signature_components_header_value) =
    encode_signature_components_header(&signature_components);

  let secret_key_bytes = URL_SAFE
    .decode(&secret_signing_key.d)
    .map_err(|_| SignError::InvalidSigningKey)?;
  if secret_key_bytes.len() != SECRET_KEY_LENGTH {
    return Err(SignError::InvalidSigningKey);
  }
  let public_key_bytes = URL_SAFE
    .decode(&secret_signing_key.x)
    .map_err(|_| SignError::InvalidSigningKey)?;
  if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
    return Err(SignError::InvalidSigningKey);
  }
  let mut signing_key_bytes = [0u8; KEYPAIR_LENGTH];
  signing_key_bytes[0..SECRET_KEY_LENGTH].copy_from_slice(&secret_key_bytes);
  signing_key_bytes[SECRET_KEY_LENGTH..KEYPAIR_LENGTH].copy_from_slice(&public_key_bytes);
  let signing_key =
    SigningKey::from_keypair_bytes(&signing_key_bytes).map_err(|_| SignError::InvalidSigningKey)?;

  let signature_message = construct_signature_message(signature_components_bytes, http_body);

  let signature = signing_key.sign(&signature_message);
  let signature_base64 = URL_SAFE.encode(&signature.to_bytes());
  let signature_header_value = format!("{SIGNATURE_VERSION},{signature_base64}");

  Ok(SignReturnValue {
    webhook_signature_components: signature_components_header_value,
    webhook_signature: signature_header_value,
  })
}

pub struct Verifier {
  expected_recipient_id: String,
  signature_ttl_seconds: usize,
  public_verifying_key_set_url: String,
  public_verifying_key_set: PublicVerifyingKeySet,
  http_client: Client,
}

impl Verifier {
  pub fn new(
    expected_recipient_id: String,
    signature_ttl_seconds: usize,
    public_verifying_key_set_url: String,
  ) -> Result<Verifier, serde_json::Error> {
    let public_verifying_key_set = PublicVerifyingKeySet { keys: vec![] };
    Ok(Verifier {
      expected_recipient_id,
      signature_ttl_seconds,
      public_verifying_key_set_url,
      public_verifying_key_set,
      http_client: reqwest::Client::new(),
    })
  }

  // Checks that the webhook signature matches the request elements. That the webhook signature has not expired, and that the request is target to the intended recipient
  pub async fn verify(
    &mut self,
    method: &str,
    webhook_signature_components_header: &str,
    webhook_signature_header: &str,
    http_body: &[u8],
  ) -> Result<VerifyReturnValue, VerifyError> {
    let result = verify(
      method,
      webhook_signature_components_header,
      webhook_signature_header,
      http_body,
      &self.expected_recipient_id,
      self.signature_ttl_seconds,
      &self.public_verifying_key_set,
    );
    if let Err(VerifyError::PublicVerifyingKeyNotFound) = result {
      if self.refresh_jwks().await.is_err() {
        return Err(VerifyError::PublicVerifyingKeyRetrievalFailed);
      }
      return verify(
        method,
        webhook_signature_components_header,
        webhook_signature_header,
        http_body,
        &self.expected_recipient_id,
        self.signature_ttl_seconds,
        &self.public_verifying_key_set,
      );
    }
    return result;
  }

  async fn refresh_jwks(&mut self) -> Result<(), VerifyError> {
    let response = self
      .http_client
      .get(&self.public_verifying_key_set_url)
      .send()
      .await
      .map_err(|_| VerifyError::PublicVerifyingKeyRetrievalFailed)?;
    if response.status() != StatusCode::OK {
      return Err(VerifyError::PublicVerifyingKeyRetrievalFailed);
    }
    let key_set = response
      .json::<PublicVerifyingKeySet>()
      .await
      .map_err(|_| VerifyError::PublicVerifyingKeyRetrievalFailed)?;
    self.public_verifying_key_set = key_set;
    Ok(())
  }
}

pub fn verify(
  method: &str,
  webhook_signature_components_header: &str,
  webhook_signature_header: &str,
  http_body: &[u8],
  expected_recipient_id: &str,
  signature_ttl_seconds: usize,
  public_verifying_key_set: &PublicVerifyingKeySet,
) -> Result<VerifyReturnValue, VerifyError> {
  let now = seconds_since_unix_epoch();
  verify_with_time(
    method,
    webhook_signature_components_header,
    webhook_signature_header,
    http_body,
    expected_recipient_id,
    signature_ttl_seconds,
    public_verifying_key_set,
    now,
  )
}

pub fn verify_with_time(
  method: &str,
  webhook_signature_components_header: &str,
  webhook_signature_header: &str,
  http_body: &[u8],
  expected_recipient_id: &str,
  signature_ttl_seconds: usize,
  public_verifying_key_set: &PublicVerifyingKeySet,
  now: u64,
) -> Result<VerifyReturnValue, VerifyError> {
  if method != "POST" {
    return Err(VerifyError::InvalidSignature);
  }
  // Todo: Make repo format and fix script
  let signature_components_encoded = split_versioned_header(webhook_signature_components_header)
    .get(SIGNATURE_VERSION)
    .ok_or(VerifyError::InvalidSignature)?
    .clone();
  let signature_components_bytes = URL_SAFE
    .decode(signature_components_encoded)
    .map_err(|_| VerifyError::InvalidSignature)?;
  let signature_components =
    serde_json::from_slice::<SignatureComponents>(&signature_components_bytes)
      .map_err(|_| VerifyError::InvalidSignature)?;

  let verifying_key_jwk = public_verifying_key_set
    .keys
    .iter()
    .find(|x| x.kid == signature_components.key_id)
    .ok_or(VerifyError::PublicVerifyingKeyNotFound)?;
  let public_key_bytes = URL_SAFE
    .decode(&verifying_key_jwk.x)
    .map_err(|_| VerifyError::InvalidPublicVerifyingKey)?;
  if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
    return Err(VerifyError::InvalidPublicVerifyingKey);
  };
  let mut verifying_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
  verifying_key_bytes[0..PUBLIC_KEY_LENGTH].copy_from_slice(&public_key_bytes);
  let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
    .map_err(|_| VerifyError::InvalidPublicVerifyingKey)?;

  let signature_message = construct_signature_message(signature_components_bytes, http_body);

  let signature_encoded = split_versioned_header(webhook_signature_header)
    .get(SIGNATURE_VERSION)
    .cloned()
    .ok_or(VerifyError::InvalidSignature)?
    .clone();
  let signature_bytes = URL_SAFE
    .decode(signature_encoded)
    .map_err(|_| VerifyError::InvalidSignature)?;
  let signature =
    Signature::from_slice(&signature_bytes).map_err(|_| VerifyError::InvalidSignature)?;

  let signature_is_valid = verifying_key
    .verify_strict(&signature_message, &signature)
    .is_ok();
  if !signature_is_valid {
    return Err(VerifyError::InvalidSignature);
  }

  if now > (signature_components.signed_at + signature_ttl_seconds as u64) {
    return Err(VerifyError::InvalidSignature);
  }

  if expected_recipient_id != signature_components.recipient_id {
    return Err(VerifyError::InvalidSignature);
  }

  Ok(VerifyReturnValue {
    webhook_id: signature_components.webhook_id,
  })
}

pub fn encode_signature_components_header(
  signature_components: &SignatureComponents,
) -> (Vec<u8>, String) {
  let signature_components_bytes = serde_json::to_string(signature_components)
    .expect("Internal CorrectHooks error.")
    .as_bytes()
    .to_vec();
  let signature_components_base64 = URL_SAFE.encode(&signature_components_bytes);
  let signature_components_header_value =
    format!("{SIGNATURE_VERSION},{signature_components_base64}");

  (
    signature_components_bytes,
    signature_components_header_value,
  )
}

fn construct_signature_message(
  mut signature_components_bytes: Vec<u8>,
  http_body: &[u8],
) -> Vec<u8> {
  signature_components_bytes.extend(http_body);
  signature_components_bytes
}

pub fn split_versioned_header(header: &str) -> HashMap<String, String> {
  let mut split_headers = HashMap::new();
  for versioned_value in header.split(' ') {
    let mut version_it = versioned_value.split(',');
    let version = version_it.next();
    let value = version_it.next();
    if version.is_none() || value.is_none() {
      continue;
    }
    let version = version.unwrap().to_string();
    let value = value.unwrap().to_string();
    split_headers.insert(version, value);
  }
  split_headers
}

pub fn seconds_since_unix_epoch() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as u64
}
