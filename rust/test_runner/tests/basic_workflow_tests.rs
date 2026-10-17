use correct_hooks::{SIGNATURE_VERSION, SignArgs, SignatureData, VerifyArgs};
use reqwest::Url;
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components_test};

#[tokio::test]
#[async_backtrace::framed]
async fn sign_verify_test() {
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
async fn sign_verify_large_body_test() {
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = (0..100000).map(|_| rand::random()).collect::<Vec<u8>>();
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
async fn multiple_public_keys_test() {
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let signing_key_2 = test_library.generate_secret_signing_key().await;
  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key_1.clone(), signing_key_2.clone()])
    .await
    .unwrap();

  let webhook_headers_1 = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_1,
    })
    .await
    .unwrap();

  let signature_components_1 =
    decode_signature_components_test(&webhook_headers_1.correct_hooks_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_1.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_1.correct_hooks_signature,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components_1.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components_1.webhook_id);

  let webhook_headers_2 = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_2,
    })
    .await
    .unwrap();

  let signature_components_2 =
    decode_signature_components_test(&webhook_headers_2.correct_hooks_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_2.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_2.correct_hooks_signature,
        request_body: &request_body,
      },
      signature_ttl_seconds,
      &public_key_set,
      signature_components_2.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components_2.webhook_id);
}
#[tokio::test]
#[async_backtrace::framed]
async fn sign_verify_unused_versions_test() {
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 300;

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);

  let signing_key = test_library.generate_secret_signing_key().await;
  let signing_key_alt = test_library.generate_secret_signing_key().await;

  let public_key_set = test_library
    .create_public_verifying_key_set(&vec![signing_key.clone()])
    .await
    .unwrap();

  let webhook_headers = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key,
    })
    .await
    .unwrap();

  let SignatureData {
    correct_hooks_signature_components: mut components_alt,
    correct_hooks_signature: mut signature_alt,
  } = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_alt,
    })
    .await
    .unwrap();

  let mut components_invalid = components_alt.clone();
  let mut signature_invalid = signature_alt.clone();
  components_invalid.insert(10, '~');
  signature_invalid.insert(16, 'a');

  let signature_version = SIGNATURE_VERSION[1..].parse::<usize>().unwrap();

  components_alt =
    components_alt.replace(SIGNATURE_VERSION, &format!("v{}", signature_version + 1));
  signature_alt = signature_alt.replace(SIGNATURE_VERSION, &format!("v{}", signature_version + 1));
  components_invalid =
    components_invalid.replace(SIGNATURE_VERSION, &format!("v{}", signature_version + 2));
  signature_invalid =
    signature_invalid.replace(SIGNATURE_VERSION, &format!("v{}", signature_version + 2));

  let joined_webhook_headers = SignatureData {
    correct_hooks_signature_components: vec![
      components_alt,
      webhook_headers.correct_hooks_signature_components.clone(),
      components_invalid,
    ]
    .join(" "),
    correct_hooks_signature: vec![
      signature_alt,
      signature_invalid,
      webhook_headers.correct_hooks_signature.clone(),
    ]
    .join(" "),
  };
  let signature_components =
    decode_signature_components_test(&webhook_headers.correct_hooks_signature_components);

  let verify_result = test_library
    .verify_with_time(
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &joined_webhook_headers
          .correct_hooks_signature_components,
        correct_hooks_signature: &joined_webhook_headers.correct_hooks_signature,
        request_body: &request_body,
      },
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
async fn sign_verify_special_characters_test() {
  let target_url = "https://adomain.com/नमस्ते/path".parse().unwrap();;
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
async fn sign_verify_empty_body_test() {
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "".to_string().as_bytes().to_vec();
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
      signature_ttl_seconds,
      &public_key_set,
      signature_components.signed_at + 1,
    )
    .await
    .unwrap();

  assert_eq!(verify_result.webhook_id, signature_components.webhook_id);
}
