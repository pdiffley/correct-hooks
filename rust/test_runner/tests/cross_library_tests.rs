use correct_hooks::{
  SignArgs, VerifyArgs, create_public_verifying_key_set, generate_secret_signing_key, sign,
  verify_with_time,
};
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components_test};

#[tokio::test]
#[async_backtrace::framed]
async fn generate_key_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = sign(SignArgs {
    target_url: &target_url,
    webhook_id,
    recipient_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();

  let signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let verify_result = verify_with_time(
    VerifyArgs {
      target_url: &target_url,
      method,
      correct_hooks_signature_components: &webhook_headers.correct_hooks_signature_components,
      correct_hooks_signature: &webhook_headers.correct_hooks_signature,
      request_body: &request_body,
    },
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
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = sign(SignArgs {
    target_url: &target_url,
    webhook_id,
    recipient_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();

  let signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let verify_result = verify_with_time(
    VerifyArgs {
      target_url: &target_url,
      method,
      correct_hooks_signature_components: &webhook_headers.correct_hooks_signature_components,
      correct_hooks_signature: &webhook_headers.correct_hooks_signature,
      request_body: &request_body,
    },
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
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      recipient_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let verify_result = verify_with_time(
    VerifyArgs {
      target_url: &target_url,
      method,
      correct_hooks_signature_components: &webhook_headers.correct_hooks_signature_components,
      correct_hooks_signature: &webhook_headers.correct_hooks_signature,
      request_body: &request_body,
    },
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
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();
  let public_key_set = create_public_verifying_key_set(&vec![signing_key.clone()]).unwrap();

  let webhook_headers = sign(SignArgs {
    target_url: &target_url,
    webhook_id,
    recipient_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();

  let signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers.correct_hooks_signature,
        request_body: &request_body,
      },
      recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}

#[tokio::test]
#[async_backtrace::framed]
async fn identical_signature_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  // values lead to base64 encoding with special characters and uneven bytes (that would be padded if the encoder used padding)
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": \">>>???\"}"
    .to_string()
    .as_bytes()
    .to_vec();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = generate_secret_signing_key();

  let webhook_headers_base = sign(SignArgs {
    target_url: &target_url,
    webhook_id,
    recipient_id,
    method,
    request_body: &request_body,
    secret_signing_key: &signing_key,
  })
  .unwrap();
  let webhook_headers_lib = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      recipient_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  assert_eq!(webhook_headers_base, webhook_headers_lib);
}
