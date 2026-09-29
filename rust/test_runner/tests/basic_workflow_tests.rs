use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use correct_hooks::{SIGNATURE_VERSION, SecretSigningKey, SignatureComponents, VerifyWebhookError, create_public_verifying_key_set, encode_signature_components_header, generate_secret_signing_key, sign_webhook, split_versioned_header, verify_webhook_with_time};
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components};
use uuid::Uuid;

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
async fn multiple_public_keys_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let signing_key_2 = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library.create_public_verifying_key_set(&vec![signing_key_1.clone(), signing_key_2.clone()]).await.unwrap();

  let webhook_headers_1 = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key_1,
  ).await.unwrap();

  let signature_components_1 = decode_signature_components(&webhook_headers_1.webhook_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &webhook_headers_1.webhook_signature_components,
    &webhook_headers_1.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components_1.signed_at + 1,
  ).await.unwrap();

  assert_eq!(verify_result.webhook_id, signature_components_1.webhook_id);

  let webhook_headers_2 = test_library.sign_webhook(
    recipient_id,
    webhook_id,
    method,
    &http_body,
    &signing_key_2
  ).await.unwrap();

  let signature_components_2 = decode_signature_components(&webhook_headers_2.webhook_signature_components);

  let verify_result = test_library.verify_webhook_with_time(
    method,
    &webhook_headers_2.webhook_signature_components,
    &webhook_headers_2.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components_2.signed_at + 1,
  ).await.unwrap();

  assert_eq!(verify_result.webhook_id, signature_components_2.webhook_id);
}
