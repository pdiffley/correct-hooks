use correct_hooks::{
  SecretSigningKey, SignatureComponents, VerifyError, encode_signature_components_header,
};
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components};
use uuid::Uuid;

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
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key)
    .await
    .unwrap();

  let signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let verify_result = test_library
    .verify_with_time(
      method,
      &webhook_headers.webhook_signature_components,
      &webhook_headers.webhook_signature,
      &http_body,
      expected_recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
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
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key)
    .await
    .unwrap();

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
      signature_components.signed_at + signature_ttl_seconds as u64 + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
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
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key)
    .await
    .unwrap();

  let actual_signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: "212345432543".to_string(),
    webhook_id: actual_signature_components.webhook_id,
    signed_at: actual_signature_components.signed_at,
    key_id: actual_signature_components.key_id,
  };

  let (_, invalid_signature_components_header_value) =
    encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library
    .verify_with_time(
      method,
      &invalid_signature_components_header_value,
      &webhook_headers.webhook_signature,
      &http_body,
      recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
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
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key)
    .await
    .unwrap();

  let actual_signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: recipient_id.to_string(),
    webhook_id: Uuid::new_v4().to_string(),
    signed_at: actual_signature_components.signed_at,
    key_id: actual_signature_components.key_id,
  };

  let (_, invalid_signature_components_header_value) =
    encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library
    .verify_with_time(
      method,
      &invalid_signature_components_header_value,
      &webhook_headers.webhook_signature,
      &http_body,
      recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
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
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key)
    .await
    .unwrap();

  let actual_signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: actual_signature_components.recipient_id,
    webhook_id: actual_signature_components.webhook_id,
    signed_at: actual_signature_components.signed_at + 1,
    key_id: actual_signature_components.key_id,
  };

  let (_, invalid_signature_components_header_value) =
    encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library
    .verify_with_time(
      method,
      &invalid_signature_components_header_value,
      &webhook_headers.webhook_signature,
      &http_body,
      recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_public_key_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let signing_key_1_value = serde_json::to_value(&signing_key_1).unwrap();
  let signing_key_2 = test_library.generate_secret_signing_key().await;
  let mut signing_key_2_value = serde_json::to_value(&signing_key_2).unwrap();
  signing_key_2_value["kid"] = signing_key_1_value["kid"].clone();
  let signing_key_2 = serde_json::from_value::<SecretSigningKey>(signing_key_2_value).unwrap();
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key_2.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key_1)
    .await
    .unwrap();

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
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
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
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key)
    .await
    .unwrap();

  let actual_signature_components =
    decode_signature_components(&webhook_headers.webhook_signature_components);

  let invalid_signature_components = SignatureComponents {
    recipient_id: actual_signature_components.recipient_id,
    webhook_id: actual_signature_components.webhook_id,
    signed_at: actual_signature_components.signed_at + 1,
    key_id: Uuid::new_v4(),
  };

  let (_, invalid_signature_components_header_value) =
    encode_signature_components_header(&invalid_signature_components);

  let verify_result = test_library
    .verify_with_time(
      method,
      &invalid_signature_components_header_value,
      &webhook_headers.webhook_signature,
      &http_body,
      recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::PublicVerifyingKeyNotFound));
}
