use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};

use ed25519_dalek::{KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub const SIGNATURE_VERSION: &'static str = "v1";
// Todo: check if catch_unwind is necessary in our code

#[derive(Serialize, Deserialize)]
struct SecretJwk {
  // Todo: confirm this serializes the way we would expect
  kid: Uuid,
  alg: String,
  kty: String,
  crv: String,
  x: String,
  d: String,
}

#[derive(Serialize, Deserialize)]
struct PublicJwk {
  kid: Uuid,
  alg: String,
  kty: String,
  crv: String,
  x: String,
}

#[derive(Serialize, Deserialize)]
struct PublicJwkSet {
  keys: Vec<PublicJwk>
}

pub fn generate_key() -> String {
  let key_id = Uuid::new_v4();
  let signing_key: SigningKey = SigningKey::generate(&mut rand::rng());
  let secret_key = URL_SAFE_NO_PAD.encode(signing_key.as_bytes());
  let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
  // See RFC 9864 for the alg field value and RFC 8037 for everything else
  let jwk = SecretJwk {
    kid: key_id,
    alg: "Ed25519".to_string(),
    kty: "OKP".to_string(),
    crv: "Ed25519".to_string(),
    x: public_key,
    d: secret_key,
  };

  let jwk_str = serde_json::to_string(&jwk).unwrap();

  jwk_str 
}

// Vec of private keys to public key set json string
pub fn create_public_verifying_key_set_json_string(private_signing_keys: &[String]) -> String {
  let mut public_jwks = PublicJwkSet { keys: vec![] };
  for private_key in private_signing_keys {
    // Todo: validate key structure()
    let public_key: PublicJwk = serde_json::from_str(private_key).unwrap();
    public_jwks.keys.push(public_key);
  }
  // We know this unwrap will succeed
  serde_json::to_string(&public_jwks).unwrap()
}


// headers
// webhook-signature-components: <version>,<base64 encoded signature components>
// webhook-signature: <version>,<base64 encoded signature>
//   - to construct the signature to sign, concatenate the values of the signature components
//   - no periods because no one sees the unsigned version of the signature

pub struct SignWebhookReturn {
  pub webhook_signature_components: String,
  pub webhook_signature: String,
  pub error: String,
}

// Todo: Signing the whole json object could avoid any json parsing issues
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureComponents {
  recipient_id: String,
  webhook_id: String,
  signed_at: u64,
  key_id: Uuid,
}

pub fn sign_webhook(recipient_id: &str, webhook_id: &str, method: &str, http_body: &[u8], signing_key: &str) -> SignWebhookReturn {
  if method != "POST" {
    // Todo: return error
  }

  // Todo: validate key structure
  let signing_key_jwk: SecretJwk = serde_json::from_str(&signing_key).unwrap();
  let key_id = signing_key_jwk.kid;
  let signed_at = seconds_since_unix_epoch();

  let signature_components = SignatureComponents {
    recipient_id: recipient_id.to_string(), 
    webhook_id: webhook_id.to_string(),
    signed_at,
    key_id
  };

  let signature_components_base64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&signature_components).unwrap().as_bytes());
  let signature_components_header_value = format!("{SIGNATURE_VERSION},{signature_components_base64}");

  // Todo: Convert panics into returnable errors
  // Todo: check that the key fails if the bytes are reversed.
  let secret_key_bytes = URL_SAFE_NO_PAD.decode(&signing_key_jwk.d).unwrap();
  assert!(secret_key_bytes.len() == SECRET_KEY_LENGTH);
  let public_key_bytes = URL_SAFE_NO_PAD.decode(&signing_key_jwk.x).unwrap();
  assert!(public_key_bytes.len() == PUBLIC_KEY_LENGTH);
  let mut signing_key_bytes = [0u8; KEYPAIR_LENGTH];
  signing_key_bytes[0..SECRET_KEY_LENGTH].copy_from_slice(&secret_key_bytes);
  signing_key_bytes[SECRET_KEY_LENGTH..KEYPAIR_LENGTH].copy_from_slice(&public_key_bytes);
  let signing_key = SigningKey::from_keypair_bytes(&signing_key_bytes).unwrap();

  let signature_message = construct_signature_message(&signature_components, http_body);

  let signature = signing_key.sign(&signature_message);
  let signature_base64 = URL_SAFE_NO_PAD.encode(&signature.to_bytes());
  let signature_header_value = format!("{SIGNATURE_VERSION},{signature_base64}");

  SignWebhookReturn { webhook_signature_components: signature_components_header_value, webhook_signature: signature_header_value, error: "".to_string() }
}

pub struct VerifyWebhookReturn {
  pub webhook_id: String,
  pub error: String,
}

// Checks that the webhook signature matches the request elements. That the webhook signature has not expired, and that the request is target to the intended recipient
// Todo: Add error return value
pub fn verify_webhook(
  method: &str, webhook_signature_components_header: &str, webhook_signature_header: &str, http_body: &[u8], expected_recipient_id: &str, signature_ttl_seconds: usize, public_verifying_key_set: &str) -> VerifyWebhookReturn {
  if method != "POST" {
    // Todo: return error
  }

  // Todo: Return error instead of unwrap
  let signature_components_encoded = split_versioned_header(webhook_signature_components_header).get(SIGNATURE_VERSION).unwrap().clone();
  let signature_components_bytes = URL_SAFE_NO_PAD.decode(signature_components_encoded).unwrap();
  let signature_components_str = String::from_utf8(signature_components_bytes).unwrap();
  let signature_components = serde_json::from_str::<SignatureComponents>(&signature_components_str).unwrap();

  // Todo: Return key not found error or other trigger for retry logic
  let jwks = serde_json::from_str::<PublicJwkSet>(public_verifying_key_set).unwrap();
  let verifying_key_jwk = jwks.keys.iter().find(|x| x.kid == signature_components.key_id).unwrap();
  // Todo: Return better key errors
  let public_key_bytes = URL_SAFE_NO_PAD.decode(&verifying_key_jwk.x).unwrap();
  assert!(public_key_bytes.len() == PUBLIC_KEY_LENGTH);
  let mut verifying_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
  verifying_key_bytes[0..PUBLIC_KEY_LENGTH].copy_from_slice(&public_key_bytes);
  let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes).unwrap();

  let signature_message = construct_signature_message(&signature_components, http_body);
  
  let signature_encoded = split_versioned_header(webhook_signature_header).get(SIGNATURE_VERSION).cloned().unwrap();
  let signature_bytes = URL_SAFE_NO_PAD.decode(signature_encoded).unwrap();
  let signature = Signature::from_slice(&signature_bytes).unwrap();

  let signature_is_valid = verifying_key.verify_strict(&signature_message, &signature).is_ok();
  if !signature_is_valid {
    // Todo: Return error?
    return VerifyWebhookReturn {
      webhook_id: "".to_string(),
      error: "AUTH_FAILURE".to_string(),
    };
  }

  let now = seconds_since_unix_epoch();
  if now > (signature_components.signed_at + signature_ttl_seconds as u64) {
    return VerifyWebhookReturn {
      webhook_id: "".to_string(),
      error: "AUTH_FAILURE".to_string(),
    };
  }

  if expected_recipient_id != signature_components.recipient_id {
    return VerifyWebhookReturn {
      webhook_id: "".to_string(),
      error: "AUTH_FAILURE".to_string(),
    };
  }

  VerifyWebhookReturn {
    webhook_id: signature_components.webhook_id.clone(),
    error: "".to_string(),
  }
}

fn construct_signature_message(signature_components: &SignatureComponents, http_body: &[u8]) -> Vec<u8> {
  let mut signature_message = format!("{}{}{}{}", 
    signature_components.recipient_id, 
    signature_components.webhook_id, 
    signature_components.signed_at, 
    signature_components.key_id)
    .as_bytes().into_iter().cloned().collect::<Vec<u8>>();
  signature_message.extend(http_body);
  signature_message
}

fn split_versioned_header(header: &str) -> HashMap<String, String> {
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

fn seconds_since_unix_epoch() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as u64
}
