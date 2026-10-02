use correct_hooks::{
  create_public_verifying_key_set, generate_secret_signing_key, sign, verify_with_time,
};
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components};

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

  let webhook_headers = sign(recipient_id, webhook_id, method, &http_body, &signing_key).unwrap();

  let signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = verify_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  )
  .unwrap();

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
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = sign(recipient_id, webhook_id, method, &http_body, &signing_key).unwrap();

  let signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = verify_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  )
  .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn sign_webhook_test() {
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let recipient_id = "1123451432543>>>???";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key)
    .await
    .unwrap();

  let signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = verify_with_time(
    method,
    &webhook_headers.webhook_signature_components,
    &webhook_headers.webhook_signature,
    &http_body,
    recipient_id,
    signature_ttl_seconds,
    &public_key_set,
    signature_components.signed_at + 1,
  )
  .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn verify_webhook_test() {
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let recipient_id = "11234521432543>>>???";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = sign(recipient_id, webhook_id, method, &http_body, &signing_key).unwrap();

  let signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = test_library
    .verify_with_time(
      method,
      &webhook_headers.webhook_signature_components,
      &webhook_headers.webhook_signature,
      &http_body,
      recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}
