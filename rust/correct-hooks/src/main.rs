use correct_hooks::{create_public_verifying_key_set_json_string, generate_key};


fn main() {
  let key = generate_key();
  create_public_verifying_key_set_json_string(&vec![key]);
}