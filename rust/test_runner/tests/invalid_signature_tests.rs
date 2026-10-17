use correct_hooks::{
  SecretSigningKey, SignArgs, SignatureComponents, VerifyArgs, VerifyError,
  encode_signature_components, version_header_value,
};
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components_test};
use uuid::Uuid;

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_target_url_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let expected_target_url = "https://adomain.com/a/patha".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &expected_target_url,
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
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_method_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let expected_method = "PUT";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method: expected_method,
        correct_hooks_signature_components: &webhook_headers.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers.correct_hooks_signature,
        request_body: &request_body,
      },
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
async fn expired_signature_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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
      signature_components.signed_at + signature_ttl_seconds + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn in_the_future_signature_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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
      signature_components.signed_at - signature_ttl_seconds - 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_recipient_id_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers.correct_hooks_signature,
        request_body: &request_body,
      },
      Uuid::new_v4(),
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_signature_components_webhook_id_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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

  let actual_signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let invalid_signature_components = SignatureComponents {
    webhook_id: Uuid::new_v4(),
    key_id: actual_signature_components.key_id,
    signed_at: actual_signature_components.signed_at,
  };

  let encoded_signature_components = encode_signature_components(&invalid_signature_components);
  let invalid_signature_components_header_value =
    version_header_value(&encoded_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &invalid_signature_components_header_value,
        correct_hooks_signature: &webhook_headers.correct_hooks_signature,
        request_body: &request_body,
      },
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
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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

  let actual_signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let invalid_signature_components = SignatureComponents {
    webhook_id: actual_signature_components.webhook_id,
    key_id: actual_signature_components.key_id,
    signed_at: actual_signature_components.signed_at + 1,
  };

  let encoded_signature_components = encode_signature_components(&invalid_signature_components);
  let invalid_signature_components_header_value =
    version_header_value(&encoded_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &invalid_signature_components_header_value,
        correct_hooks_signature: &webhook_headers.correct_hooks_signature,
        request_body: &request_body,
      },
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
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

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
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      recipient_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_1,
    })
    .await
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
    .await;

  assert_eq!(verify_result, Err(VerifyError::InvalidSignature));
}

#[tokio::test]
#[async_backtrace::framed]
async fn missing_public_key_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

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

  let actual_signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let invalid_signature_components = SignatureComponents {
    webhook_id: actual_signature_components.webhook_id,
    key_id: Uuid::new_v4(),
    signed_at: actual_signature_components.signed_at + 1,
  };

  let encoded_signature_components = encode_signature_components(&invalid_signature_components);
  let invalid_signature_components_header_value =
    version_header_value(&encoded_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &invalid_signature_components_header_value,
        correct_hooks_signature: &webhook_headers.correct_hooks_signature,
        request_body: &request_body,
      },
      recipient_id,
      signature_ttl_seconds,
      &public_key_set,
      actual_signature_components.signed_at + 1,
    )
    .await;

  assert_eq!(verify_result, Err(VerifyError::PublicVerifyingKeyNotFound));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_sign_args_method_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "GETTTTT";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;

  let sign_result = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      recipient_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await;

  assert_eq!(sign_result, Err(correct_hooks::SignError::InvalidArgs));
}

#[tokio::test]
#[async_backtrace::framed]
async fn invalid_sign_args_method_lower_case_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "post";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;

  let sign_result = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      recipient_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await;

  assert_eq!(sign_result, Err(correct_hooks::SignError::InvalidArgs));
}
