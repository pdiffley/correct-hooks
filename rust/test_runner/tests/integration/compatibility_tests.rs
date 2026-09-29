use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use correct_hooks::{SIGNATURE_VERSION, SignatureComponents, VerifyWebhookError, create_public_verifying_key_set, encode_signature_components_header, generate_secret_signing_key, sign_webhook, split_versioned_header, verify_webhook_with_time};
use test_runner::test_client::CorrectHooksTestClient;
use uuid::Uuid;

#[tokio::test]
#[async_backtrace::framed]
async fn generate_key_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  ).unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn create_public_verifying_key_set_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  ).unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn sign_webhook_test() {
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let recipient_id = "1123451432543>>>???";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": \">>>???\"}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  ).unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn verify_webhook_test() {
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let recipient_id = "11234521432543>>>???";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": \">>>???\"}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  ).await.unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}


#[tokio::test]
#[async_backtrace::framed]
async fn sign_verify_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  ).await.unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn sign_verify_large_body_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body =(0..100000).map(|_| rand::random()).collect::<Vec<u8>>();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  ).await.unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_recipient_test() {
  let recipient_id = "112345432543";
  let expected_recipient_id = "112345432544";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    expected_recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  ).await;

  assert_eq!(verify_result, Err(VerifyWebhookError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn expired_signature_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + signature_ttl_seconds as u64 + 1,
  ).await;

  assert_eq!(verify_result, Err(VerifyWebhookError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_signature_components_recipient_id_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let actual_signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: "212345432543".to_string(),
    webhook_id: actual_signature_components.webhook_id,
    signed_at: actual_signature_components.signed_at,
    key_id: actual_signature_components.key_id,
  };

  let (_, invalid_signature_components_header_value) = encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &invalid_signature_components_header_value,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    actual_signature_components.signed_at + 1,
  ).await;

  assert_eq!(verify_result, Err(VerifyWebhookError::InvalidSignature));
}


#[tokio::test]
#[async_backtrace::framed]
async fn invalid_signature_components_webhook_id_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let actual_signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: recipient_id.to_string(),
    webhook_id: Uuid::new_v4().to_string(),
    signed_at: actual_signature_components.signed_at,
    key_id: actual_signature_components.key_id,
  };

  let (_, invalid_signature_components_header_value) = encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &invalid_signature_components_header_value,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    actual_signature_components.signed_at + 1,
  ).await;

  assert_eq!(verify_result, Err(VerifyWebhookError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_signature_components_signed_at_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let actual_signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: actual_signature_components.recipient_id,
    webhook_id: actual_signature_components.webhook_id,
    signed_at: actual_signature_components.signed_at + 1,
    key_id: actual_signature_components.key_id,
  };

  let (_, invalid_signature_components_header_value) = encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &invalid_signature_components_header_value,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    actual_signature_components.signed_at + 1,
  ).await;

  assert_eq!(verify_result, Err(VerifyWebhookError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn missing_public_key_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key.clone()]).await.unwrap();

  let webhook_headers = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key,
  ).await.unwrap();

  let actual_signature_components = decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: actual_signature_components.recipient_id,
    webhook_id: actual_signature_components.webhook_id,
    signed_at: actual_signature_components.signed_at + 1,
    key_id: Uuid::new_v4(),
  };

  let (_, invalid_signature_components_header_value) = encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &invalid_signature_components_header_value,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    actual_signature_components.signed_at + 1,
  ).await;

  assert_eq!(verify_result, Err(VerifyWebhookError::PublicVerifyingKeyNotFound));
}

// Todo: fail when a signature component empty value is provided

// Test with specific base64 value to test special characters and padding
// Similar test for key?

// Todo: use thiserror with rust code

// Todo: test multiple public keys 


fn decode_signature_components(webhook_signature_components_header: &str) -> SignatureComponents {
  let signature_components_encoded = split_versioned_header(webhook_signature_components_header).get(SIGNATURE_VERSION).unwrap().clone();
  let signature_components_bytes = URL_SAFE_NO_PAD.decode(&signature_components_encoded).unwrap();
  let signature_components_str = String::from_utf8(signature_components_bytes.clone()).unwrap();
  let signature_components = serde_json::from_str::<SignatureComponents>(&signature_components_str).unwrap();
  signature_components
}