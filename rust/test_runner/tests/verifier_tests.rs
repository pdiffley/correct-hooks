use correct_hooks::{SignArgs, VerifyArgs, seconds_since_unix_epoch};
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components_test};
use uuid::Uuid;

#[tokio::test]
#[async_backtrace::framed]
async fn verifier_key_id_not_found_refresh_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let public_key_set_id = Uuid::new_v4();
  let verifier_id = Uuid::new_v4();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);
  test_library
    .register_new_verifier(verifier_id, recipient_id, public_key_set_id, None, None)
    .await;

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let public_key_set_1 = test_library
    .create_public_verifying_key_set(&vec![signing_key_1.clone()])
    .await
    .unwrap();
  test_library
    .set_public_verifying_key_set(public_key_set_id, Some(public_key_set_1))
    .await;

  let webhook_headers_1 = test_library
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

  let signature_components_1 =
    decode_signature_components_test(&webhook_headers_1.correct_hooks_signature_components);

  let verify_result_1 = test_library
    .verify_with_time_with_verifier(
      verifier_id,
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_1.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_1.correct_hooks_signature,
        request_body: &request_body,
      },
      seconds_since_unix_epoch(),
    )
    .await
    .unwrap();

  assert_eq!(
    verify_result_1.webhook_id,
    signature_components_1.webhook_id
  );

  let signing_key_2 = test_library.generate_secret_signing_key().await;
  let public_key_set_2 = test_library
    .create_public_verifying_key_set(&vec![signing_key_2.clone()])
    .await
    .unwrap();
  test_library
    .set_public_verifying_key_set(public_key_set_id, Some(public_key_set_2))
    .await;

  let webhook_headers_2 = test_library
    .sign(SignArgs {
      target_url: &target_url,
      webhook_id,
      recipient_id,
      method,
      request_body: &request_body,
      secret_signing_key: &signing_key_2,
    })
    .await
    .unwrap();

  let signature_components_2 =
    decode_signature_components_test(&webhook_headers_2.correct_hooks_signature_components);

  let verify_result_2 = test_library
    .verify_with_time_with_verifier(
      verifier_id,
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_2.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_2.correct_hooks_signature,
        request_body: &request_body,
      },
      seconds_since_unix_epoch(),
    )
    .await
    .unwrap();

  assert_eq!(
    verify_result_2.webhook_id,
    signature_components_2.webhook_id
  );
}

#[tokio::test]
#[async_backtrace::framed]
async fn verifier_key_set_ttl_refresh_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let public_key_set_id = Uuid::new_v4();
  let verifier_id = Uuid::new_v4();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);
  let public_verifying_key_set_ttl = 300;
  test_library
    .register_new_verifier(
      verifier_id,
      recipient_id,
      public_key_set_id,
      None,
      Some(public_verifying_key_set_ttl),
    )
    .await;

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let public_key_set_1 = test_library
    .create_public_verifying_key_set(&vec![signing_key_1.clone()])
    .await
    .unwrap();
  test_library
    .set_public_verifying_key_set(public_key_set_id, Some(public_key_set_1))
    .await;

  let webhook_headers_1 = test_library
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

  let signature_components_1 =
    decode_signature_components_test(&webhook_headers_1.correct_hooks_signature_components);

  let verify_result_1 = test_library
    .verify_with_time_with_verifier(
      verifier_id,
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_1.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_1.correct_hooks_signature,
        request_body: &request_body,
      },
      signature_components_1.signed_at,
    )
    .await
    .unwrap();

  assert_eq!(
    verify_result_1.webhook_id,
    signature_components_1.webhook_id
  );

  let signing_key_2 = test_library.generate_secret_signing_key().await;
  let public_key_set_2 = test_library
    .create_public_verifying_key_set(&vec![signing_key_2.clone()])
    .await
    .unwrap();
  test_library
    .set_public_verifying_key_set(public_key_set_id, Some(public_key_set_2))
    .await;

  let webhook_headers_old_key = test_library
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

  let signature_components_old_key =
    decode_signature_components_test(&webhook_headers_old_key.correct_hooks_signature_components);

  let verify_result_old_key = test_library
    .verify_with_time_with_verifier(
      verifier_id,
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_old_key
          .correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_old_key.correct_hooks_signature,
        request_body: &request_body,
      },
      signature_components_old_key.signed_at + public_verifying_key_set_ttl + 1,
    )
    .await;

  assert!(verify_result_old_key.is_err());
}

#[tokio::test]
#[async_backtrace::framed]
async fn verifier_key_set_ttl_soft_test() {
  let recipient_id = "9f1c2a4e-3b7d-4c58-a6e1-52d8b0c47f93".parse().unwrap();
  let target_url = "https://adomain.com/a/path".parse().unwrap();
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba".parse().unwrap();
  let method = "POST";
  let request_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();

  let public_key_set_id = Uuid::new_v4();
  let verifier_id = Uuid::new_v4();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);
  let public_verifying_key_set_ttl = 100;
  test_library
    .register_new_verifier(
      verifier_id,
      recipient_id,
      public_key_set_id,
      None,
      Some(public_verifying_key_set_ttl),
    )
    .await;

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let public_key_set_1 = test_library
    .create_public_verifying_key_set(&vec![signing_key_1.clone()])
    .await
    .unwrap();
  test_library
    .set_public_verifying_key_set(public_key_set_id, Some(public_key_set_1))
    .await;

  let webhook_headers_1 = test_library
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

  let signature_components_1 =
    decode_signature_components_test(&webhook_headers_1.correct_hooks_signature_components);

  let verify_result_1 = test_library
    .verify_with_time_with_verifier(
      verifier_id,
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_1.correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_1.correct_hooks_signature,
        request_body: &request_body,
      },
      signature_components_1.signed_at,
    )
    .await
    .unwrap();

  assert_eq!(
    verify_result_1.webhook_id,
    signature_components_1.webhook_id
  );

  test_library
    .set_public_verifying_key_set(public_key_set_id, None)
    .await;

  let webhook_headers_old_key = test_library
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

  let signature_components_old_key =
    decode_signature_components_test(&webhook_headers_old_key.correct_hooks_signature_components);

  let verify_result_old_key = test_library
    .verify_with_time_with_verifier(
      verifier_id,
      VerifyArgs {
        target_url: &target_url,
        method,
        correct_hooks_signature_components: &webhook_headers_old_key
          .correct_hooks_signature_components,
        correct_hooks_signature: &webhook_headers_old_key.correct_hooks_signature,
        request_body: &request_body,
      },
      signature_components_old_key.signed_at + public_verifying_key_set_ttl + 1,
    )
    .await
    .unwrap();

  assert_eq!(
    verify_result_old_key.webhook_id,
    signature_components_old_key.webhook_id
  );
}
