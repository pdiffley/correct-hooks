use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components};
use uuid::Uuid;

// make a jwks id
// create a client
// function register jwks (takes id and jwks)
// function new verifier (takes an id, and tells the server to make a verifier)
// function verify with

#[tokio::test]
#[async_backtrace::framed]
async fn verifier_test() {
  let recipient_id = "112345432543";
  let webhook_id = "6c22e7f3-753e-4076-8bf2-bd923dbdd6ba";
  let method = "POST";
  let http_body = "{\"testfield\": 234}".to_string().as_bytes().to_vec();
  let signature_ttl_seconds = 3600;

  let public_key_set_id = Uuid::new_v4();
  let verifier_id = Uuid::new_v4();

  let test_server_port: u16 = std::env::var("TEST_SERVER_PORT").unwrap().parse().unwrap();
  let test_library = CorrectHooksTestClient::new(test_server_port);
  test_library
    .register_new_verifier(
      verifier_id,
      recipient_id,
      signature_ttl_seconds,
      public_key_set_id,
    )
    .await;

  let signing_key_1 = test_library.generate_secret_signing_key().await;
  let public_key_set_1 = test_library
    .create_public_verifying_key_set(&vec![signing_key_1.clone()])
    .await
    .unwrap();
  test_library
    .set_public_verifying_key_set(public_key_set_id, &public_key_set_1)
    .await;

  let webhook_headers_1 = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key_1)
    .await
    .unwrap();

  let signature_components_1 =
    decode_signature_components(&webhook_headers_1.webhook_signature_components);

  let verify_result_1 = test_library
    .verify_with_verifier(
      verifier_id,
      method,
      &webhook_headers_1.webhook_signature_components,
      &webhook_headers_1.webhook_signature,
      &http_body,
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
    .set_public_verifying_key_set(public_key_set_id, &public_key_set_2)
    .await;

  let webhook_headers_2 = test_library
    .sign(recipient_id, webhook_id, method, &http_body, &signing_key_2)
    .await
    .unwrap();

  let signature_components_2 =
    decode_signature_components(&webhook_headers_2.webhook_signature_components);

  let verify_result_2 = test_library
    .verify_with_verifier(
      verifier_id,
      method,
      &webhook_headers_2.webhook_signature_components,
      &webhook_headers_2.webhook_signature,
      &http_body,
    )
    .await
    .unwrap();

  assert_eq!(
    verify_result_2.webhook_id,
    signature_components_2.webhook_id
  );
}

// verify a request with a verifier

// test server has
//   register jwks endpoint
//   get jwks endpoint with path component hold uuid
//   new verifier endpoint - takes uuid for verifier, and verifier args
//   verify with verifier endpoint - takes uuid for the verifier and the verify args

// change with signing key with a public key update and succeed
