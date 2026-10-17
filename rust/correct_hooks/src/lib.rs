use std::{
  collections::HashMap,
  sync::Arc,
  time::{SystemTime, UNIX_EPOCH},
};

use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{
  KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, Signature, Signer, SigningKey, VerifyingKey,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

/// The signature version produced by this version of the library.
pub const SIGNATURE_VERSION: &'static str = "v1";
const DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS: u64 = 300;
const DEFAULT_SIGNATURE_TTL_SECONDS: u64 = 300;

/// A key used to sign requests.
///
/// Must be kept secret and should only be held by the signer.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct SecretSigningKey {
  kid: Uuid,
  kty: String,
  crv: String,
  x: String,
  d: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PublicJwk {
  kid: Uuid,
  kty: String,
  crv: String,
  x: String,
}

/// A set of public keys used to verify signed requests.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicVerifyingKeySet {
  keys: Vec<PublicJwk>,
}

/// This struct is only public for internal testing purposes and will be made private in a future version of this library.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureComponents {
  pub webhook_id: Uuid,
  pub key_id: Uuid,
  pub signed_at: u64,
}

/// Errors that can be returned from [`create_public_verifying_key_set`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum CreatePublicVerifyingKeySetError {
  InvalidKeyFound,
}

/// The arguments to the [`sign`] function.
#[derive(Clone, Copy)]
pub struct SignArgs<'a> {
  /// An id for the webhook.
  ///
  /// This id should be unique for the event triggering the webhook, and should
  /// be reused for any delivery retries.
  pub webhook_id: Uuid,
  /// The webhook consumer's id.
  ///
  /// This id must be provided by the webhook producer, and not taken as an input from the webhook consumer
  pub recipient_id: Uuid, 
  /// The url the webhook is being sent to.
  ///
  /// Must be the exact url string provided by the webhook consumer.
  pub target_url: &'a Url,
  /// The HTTP method the webhook will be sent with.
  pub method: &'a str,
  /// The exact body of the webhook request as bytes.
  pub request_body: &'a [u8],
  /// The [`SecretSigningKey`] the signature will be signed with.
  pub secret_signing_key: &'a SecretSigningKey,
}

/// Header values to set on the webhook request.
///
/// You must set the request headers `correct-hooks-signature-components` and `correct-hooks-signature` to these values.
/// Webhook consumers will pass the values of the headers to the verify function. Future versions of Correct Hooks with
/// convenience functions that verify specific framework's request objects will expect these exact header names to be set.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignatureData {
  /// Set the header `correct-hooks-signature-components` to this value.
  pub correct_hooks_signature_components: String,
  /// Set the header `correct-hooks-signature` to this value.
  pub correct_hooks_signature: String,
}

/// Errors returned by the [`sign`] function.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SignError {
  InvalidArgs,
  InvalidSigningKey,
}

/// The arguments to [`Verifier::verify`] and [`Verifier::verify_with_time`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyArgs<'a> {
  /// The url your endpoint is receiving requests at.
  ///
  /// `target_url` needs to be the exact string given to the webhook provider,
  /// preferably retrieved from an environment variable or hardcoded.
  pub target_url: &'a Url,
  /// The HTTP method the request was sent with. Can be extracted from the request.
  pub method: &'a str,
  /// The value from the request's `correct-hooks-signature-components` header.
  pub correct_hooks_signature_components: &'a str,
  /// The value from the request's `correct-hooks-signature` header.
  pub correct_hooks_signature: &'a str,
  /// The unparsed request body as bytes.
  pub request_body: &'a [u8],
}

/// Validated request data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedData {
  /// The validated `webhook_id` for the request. These id's can be put in a shared cache
  /// by the webhook consumer and checked against for the highest level of replay protection.
  pub webhook_id: Uuid,
}

/// Errors returned by [`Verifier::verify`]. Receiving any of these errors indicates that a request
/// is invalid and should be rejected with a 4xx error code.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum VerifyError {
  /// The key needed to verify the request was not found in the verifying key set provided by the
  /// webhook provider.
  ///
  /// If you receive this error consistently, the webhook provider may need to update their
  /// published public verifying key set. In some specific cases, this error can also be returned
  /// due to an invalid signature.
  PublicVerifyingKeyNotFound,
  /// The webhook provider's public verifying key set could not be retrieved.
  ///
  /// If you get this error, likely either the `public_verifying_key_set_url` the [`Verifier`] was created with is incorrect,
  /// or the webhook producer's endpoint is unavailable.
  PublicVerifyingKeyRetrievalFailed,
  InvalidSignature,
  /// The public verifying key set retrieved from `public_verifying_key_set_url` could not be parsed and likely
  /// needs to be updated by the webhook producer.
  InvalidPublicVerifyingKey,
}

/// Generate a new [`SecretSigningKey`].
pub fn generate_secret_signing_key() -> SecretSigningKey {
  let key_id = Uuid::new_v4();
  let signing_key: SigningKey = SigningKey::generate(&mut rand::rng());
  let secret_key = encode_base64(signing_key.as_bytes());
  let public_key = encode_base64(signing_key.verifying_key().as_bytes());
  let jwk = SecretSigningKey {
    kid: key_id,
    kty: "OKP".to_string(),
    crv: "Ed25519".to_string(),
    x: public_key,
    d: secret_key,
  };

  jwk
}

/// Creates a [`PublicVerifyingKeySet`] from a list of [`SecretSigningKey`].
///
/// The returned [`PublicVerifyingKeySet`] can be used to verify requests signed
/// by any of the `secret_signing_keys`.
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

/// Creates a signature for a webhook request and returns the signature headers that should be set on the request.
///
/// You must set the request headers `correct-hooks-signature-components` and `correct-hooks-signature` to these values.
/// Webhook consumers will pass the values of the headers to the verify function. Future versions of Correct Hooks with
/// convenience functions that verify specific framework's request objects will expect these exact header names to be set.
///
/// `sign` should be called every time a webhook delivery is attempted. The signed headers should not be reused
/// between retried delivery attempts.
pub fn sign(args: SignArgs<'_>) -> Result<SignatureData, SignError> {
  let SignArgs {
    webhook_id,
    recipient_id,
    target_url,
    method,
    request_body,
    secret_signing_key,
  } = args;

  if webhook_id.get_version_num() != 4 {
    return Err(SignError::InvalidArgs)
  }

  if recipient_id.get_version_num() != 4 {
    return Err(SignError::InvalidArgs)
  }

  if !is_valid_http_method(method) {
    return Err(SignError::InvalidArgs);
  }

  let key_id = secret_signing_key.kid;
  let signed_at = seconds_since_unix_epoch();

  let signature_components = SignatureComponents {
    webhook_id,
    key_id,
    signed_at,
  };

  let encoded_signature_components = encode_signature_components(&signature_components);
  let signature_components_header = version_header_value(&encoded_signature_components);

  let secret_key_bytes =
    decode_base64(&secret_signing_key.d).map_err(|_| SignError::InvalidSigningKey)?;
  if secret_key_bytes.len() != SECRET_KEY_LENGTH {
    return Err(SignError::InvalidSigningKey);
  }
  let public_key_bytes =
    decode_base64(&secret_signing_key.x).map_err(|_| SignError::InvalidSigningKey)?;
  if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
    return Err(SignError::InvalidSigningKey);
  }
  let mut signing_key_bytes = [0u8; KEYPAIR_LENGTH];
  signing_key_bytes[0..SECRET_KEY_LENGTH].copy_from_slice(&secret_key_bytes);
  signing_key_bytes[SECRET_KEY_LENGTH..KEYPAIR_LENGTH].copy_from_slice(&public_key_bytes);
  let signing_key =
    SigningKey::from_keypair_bytes(&signing_key_bytes).map_err(|_| SignError::InvalidSigningKey)?;

  let signature_message = construct_signature_message(&signature_components, recipient_id, target_url, method, request_body);

  let signature = signing_key.sign(&signature_message);
  let signature_base64 = encode_base64(&signature.to_bytes());
  let signature_header_value = version_header_value(&signature_base64);

  Ok(SignatureData {
    correct_hooks_signature_components: signature_components_header,
    correct_hooks_signature: signature_header_value,
  })
}

/// Arguments for creating a [`Verifier`].
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifierConfig {
  /// Your webhook consumer id. 
  ///
  /// This id must be provided to you in advance by the webhook producer and should never be extracted
  /// from a webhook request.
  pub recipient_id: Uuid,
  /// The url serving the webhook provider's verfiying key set.
  ///
  /// The webhook provider should give you this url.
  pub public_verifying_key_set_url: String,
  /// How long a signature is considered valid. Defaults to 300 seconds (5 minutes).
  ///
  /// In most cases, the default parameter should be used.
  /// This parameter should not be set to a value larger than 300 (may be enforced in the future).
  pub signature_ttl_seconds: Option<u64>,
  /// How long a retrieved `public_verifying_key_set` can be used before it is considered stale. Defaults to 300 seconds (5 minutes).
  ///
  /// In most cases, the default parameter should be used.
  /// This parameter should not be set to a value larger than 300 (may be enforced in the future).
  pub public_verifying_key_set_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug)]
struct PublicVerifyingKeySetData {
  pub key_set: PublicVerifyingKeySet,
  pub refreshed_at: u64,
  pub refresh_id: Uuid,
}

/// Verifier for signed webhook requests
///
/// The [`Verifier`] handles retrieving and refreshing the webhook producer's verifying key set for you.
///
/// Ideally you should create one [`Verifier`] when your backend instance starts and reuse it for all requests sent to that backend instance.
///
/// You do not have to wrap the [`Verifier`] in an [`Rc`](std::rc::Rc) or [`Arc`] to reuse it because it already uses [`Arc`]s internally.
#[derive(Clone, Debug)]
pub struct Verifier {
  recipient_id: Uuid,
  public_verifying_key_set_url: String,
  signature_ttl_seconds: u64,
  public_verifying_key_set_ttl_seconds: u64,
  public_verifying_key_set: Arc<std::sync::RwLock<Arc<PublicVerifyingKeySetData>>>,
  public_verifying_key_set_refresh_lock: Arc<tokio::sync::Mutex<()>>,
  http_client: Client,
}

// Todo: When loading a public jwks, exclude any keys that have unexpected fields
// Todo: Add an alternate constructor for the verifier that takes a jwks directly for testing.
impl Verifier {
  /// Create a new [`Verifier`].
  pub fn new(config: VerifierConfig) -> Verifier {
    let public_verifying_key_set = Arc::new(std::sync::RwLock::new(Arc::new(
      PublicVerifyingKeySetData {
        key_set: PublicVerifyingKeySet { keys: vec![] },
        refreshed_at: 0,
        refresh_id: Uuid::new_v4(),
      },
    )));
    let public_verifying_key_set_refresh_lock = Arc::new(tokio::sync::Mutex::new(()));
    Verifier {
      recipient_id: config.recipient_id,
      public_verifying_key_set_url: config.public_verifying_key_set_url,
      signature_ttl_seconds: config
        .signature_ttl_seconds
        .unwrap_or(DEFAULT_SIGNATURE_TTL_SECONDS),
      public_verifying_key_set_ttl_seconds: config
        .public_verifying_key_set_ttl_seconds
        .unwrap_or(DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS),
      public_verifying_key_set,
      public_verifying_key_set_refresh_lock,
      http_client: reqwest::Client::new(),
    }
  }

  /// Verifies a request and returns validated information from the Correct Hooks request headers.
  ///
  /// This function confirms that the provided request signature is valid, that the signature has not expired, and that the request was sent to the intended endpoint.
  ///
  /// Any returned error indicates that the signature could not be verified and the request should be rejected with a 4xx error
  pub async fn verify(&self, args: VerifyArgs<'_>) -> Result<VerifiedData, VerifyError> {
    let now = seconds_since_unix_epoch();
    self.verify_with_time(args, now).await
  }

  /// The same as [`Verifier::verify`] but with the current time provided by the caller, which
  /// can be useful for testing.
  ///
  /// # Arguments
  ///
  /// * `now` - The current time in seconds since Unix epoch.
  pub async fn verify_with_time(
    &self,
    args: VerifyArgs<'_>,
    now: u64,
  ) -> Result<VerifiedData, VerifyError> {
    let public_verifying_key_set = self.current_key_set();
    if now > public_verifying_key_set.refreshed_at + self.public_verifying_key_set_ttl_seconds {
      let _ = self.refresh_jwks(public_verifying_key_set.refresh_id).await;
    }

    let public_verifying_key_set = self.current_key_set();
    let result = verify_with_time(
      args,
      self.recipient_id,
      self.signature_ttl_seconds,
      &public_verifying_key_set.key_set,
      now,
    );
    if let Err(VerifyError::PublicVerifyingKeyNotFound) = result {
      if self
        .refresh_jwks(public_verifying_key_set.refresh_id)
        .await
        .is_err()
      {
        return Err(VerifyError::PublicVerifyingKeyRetrievalFailed);
      }
      let public_verifying_key_set = self.current_key_set();
      return verify_with_time(
        args,
        self.recipient_id,
        self.signature_ttl_seconds,
        &public_verifying_key_set.key_set,
        now,
      );
    }
    return result;
  }

  async fn refresh_jwks(&self, old_refresh_id: Uuid) -> Result<(), VerifyError> {
    let _refresh_lock = self.public_verifying_key_set_refresh_lock.lock().await;
    let current_public_verifying_key_set = self.current_key_set();
    if current_public_verifying_key_set.refresh_id != old_refresh_id {
      return Ok(());
    }

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
    let new_refresh_time = seconds_since_unix_epoch();
    let new_public_verifying_key_set = Arc::new(PublicVerifyingKeySetData {
      key_set,
      refreshed_at: new_refresh_time,
      refresh_id: Uuid::new_v4(),
    });

    *self.public_verifying_key_set.write().unwrap() = new_public_verifying_key_set;
    Ok(())
  }

  fn current_key_set(&self) -> Arc<PublicVerifyingKeySetData> {
    self.public_verifying_key_set.read().unwrap().clone()
  }
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn verify_with_time(
  args: VerifyArgs<'_>,
  recipient_id: Uuid,
  signature_ttl_seconds: u64,
  public_verifying_key_set: &PublicVerifyingKeySet,
  now: u64,
) -> Result<VerifiedData, VerifyError> {
  let VerifyArgs {
    target_url,
    method,
    correct_hooks_signature_components,
    correct_hooks_signature,
    request_body,
  } = args;
  let signature_components_encoded = split_versioned_header(correct_hooks_signature_components)
    .get(SIGNATURE_VERSION)
    .ok_or(VerifyError::InvalidSignature)?
    .clone();
  let signature_components = decode_signature_components(&signature_components_encoded)
    .map_err(|_| VerifyError::InvalidSignature)?;

  if now > (signature_components.signed_at + signature_ttl_seconds)
    || now + signature_ttl_seconds < signature_components.signed_at
  {
    return Err(VerifyError::InvalidSignature);
  }

  let verifying_key_jwk = public_verifying_key_set
    .keys
    .iter()
    .find(|x| x.kid == signature_components.key_id)
    .ok_or(VerifyError::PublicVerifyingKeyNotFound)?;
  let public_key_bytes =
    decode_base64(&verifying_key_jwk.x).map_err(|_| VerifyError::InvalidPublicVerifyingKey)?;
  if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
    return Err(VerifyError::InvalidPublicVerifyingKey);
  };
  let mut verifying_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
  verifying_key_bytes[0..PUBLIC_KEY_LENGTH].copy_from_slice(&public_key_bytes);
  let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
    .map_err(|_| VerifyError::InvalidPublicVerifyingKey)?;

  let signature_message = construct_signature_message(&signature_components, recipient_id, target_url, method, request_body);

  let signature_encoded = split_versioned_header(correct_hooks_signature)
    .get(SIGNATURE_VERSION)
    .cloned()
    .ok_or(VerifyError::InvalidSignature)?
    .clone();
  let signature_bytes =
    decode_base64(&signature_encoded).map_err(|_| VerifyError::InvalidSignature)?;
  let signature =
    Signature::from_slice(&signature_bytes).map_err(|_| VerifyError::InvalidSignature)?;

  let signature_is_valid = verifying_key
    .verify_strict(&signature_message, &signature)
    .is_ok();
  if !signature_is_valid {
    return Err(VerifyError::InvalidSignature);
  }

  Ok(VerifiedData {
    webhook_id: signature_components.webhook_id,
  })
}

fn construct_signature_message(
  signature_components: &SignatureComponents,
  recipient_id: Uuid,
  target_url: &Url,
  method: &str,
  request_body: &[u8],
) -> Vec<u8> {
  let encoded_signature_components = encode_signature_components(signature_components);
  let recipient_id_base64 = encode_base64_from_string(&recipient_id.to_string());
  let target_url_base64 = encode_base64_from_string(&target_url.to_string());
  let mut signature_message = format!("{encoded_signature_components}.{recipient_id_base64}.{target_url_base64},{method}.")
    .bytes()
    .collect::<Vec<_>>();
  signature_message.extend(request_body);
  signature_message
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn version_header_value(header_value: &str) -> String {
  format!("{SIGNATURE_VERSION},{header_value}")
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
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

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn encode_signature_components(signature_components: &SignatureComponents) -> String {
  let webhook_id_base64 = encode_base64_from_string(&signature_components.webhook_id.to_string());
  let key_id_base64 = encode_base64_from_string(&signature_components.key_id.to_string());
  let signed_at_base64 = encode_base64_from_string(&signature_components.signed_at.to_string());
  let encoded_signature_components = format!(
    "{}.{}.{}",
    webhook_id_base64, key_id_base64, signed_at_base64
  );
  encoded_signature_components
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn decode_signature_components(
  encoded_signature_components: &str,
) -> Result<SignatureComponents, String> {
  let components = encoded_signature_components.split('.').collect::<Vec<_>>();
  if components.len() != 3 {
    return Err("Invalid component count".to_owned());
  }
  let webhook_id = decode_base64_to_string(components[0])?
    .parse()
    .map_err(|_| "invalid webhook_id".to_owned())?;
  let key_id = decode_base64_to_string(components[1])?
    .parse()
    .map_err(|_| "invalid key_id".to_owned())?;
  let signed_at = decode_base64_to_string(components[2])?
    .parse()
    .map_err(|_| "invalid timestamp".to_owned())?;

  let result = Ok(SignatureComponents {
    webhook_id,
    key_id,
    signed_at,
  });

  result
}

fn is_valid_http_method(method: &str) -> bool {
  matches!(
    method,
    "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
  )
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn encode_base64(data: &[u8]) -> String {
  URL_SAFE_NO_PAD.encode(data)
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn decode_base64(base64_str: &str) -> Result<Vec<u8>, DecodeError> {
  URL_SAFE_NO_PAD.decode(base64_str)
}

fn encode_base64_from_string(data: &str) -> String {
  encode_base64(data.as_bytes())
}

fn decode_base64_to_string(base64_str: &str) -> Result<String, String> {
  let data = decode_base64(base64_str).map_err(|_| "base64 decode error".to_owned())?;
  String::from_utf8(data).map_err(|_| "utf-8 failure".to_owned())
}

/// This function is only public for internal testing purposes and will be made private in a future version of this library.
pub fn seconds_since_unix_epoch() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as u64
}
