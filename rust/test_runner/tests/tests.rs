use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use correct_hooks::{SIGNATURE_VERSION, SecretSigningKey, SignatureComponents, VerifyWebhookError, create_public_verifying_key_set, encode_signature_components_header, generate_secret_signing_key, sign_webhook, split_versioned_header, verify_webhook_with_time};
use test_runner::test_client::{CorrectHooksTestClient, decode_signature_components};
use uuid::Uuid;

// Todo: fail when a signature component empty value is provided

// Todo: use thiserror with rust code
 
