#!/usr/bin/env bash

cargo fix
cargo +nightly fmt

uv run ruff check --fix
uv run ruff format

# yarn run lint:fix
# yarn run fmt