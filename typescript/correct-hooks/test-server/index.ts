import { parseArgs } from "node:util";

import { serve } from "@hono/node-server";
import { Hono } from "hono";

import {
  CreatePublicVerifyingKeySetError,
  SignError,
  Verifier,
  VerifyError,
  createPublicVerifyingKeySet,
  decodeBase64,
  generateSecretSigningKey,
  sign,
  verifyWithTime,
  type PublicVerifyingKeySet,
  type SecretSigningKey,
  type VerifierConfig,
} from "../src/index.js";

interface ApiResponse<T> {
  output: T | null;
  error: string | null;
}

interface CreatePublicVerifyingKeySetRequest {
  keys: SecretSigningKey[];
}

interface SignRequest {
  targetUrl: string;
  webhookId: string;
  recipientId: string;
  method: string;
  body: string;
  signingKey: SecretSigningKey;
}

interface VerifyWithTimeRequest {
  recipientId: string;
  targetUrl: string;
  method: string;
  correctHooksSignatureComponents: string;
  correctHooksSignature: string;
  body: string;
  signatureTtlSeconds: number;
  publicVerifyingKeySet: PublicVerifyingKeySet;
  now: number;
}

interface RegisterPublicVerifyingKeySetRequest {
  publicVerifyingKeySet?: PublicVerifyingKeySet | null;
}

interface VerifyWithTimeWithVerifierRequest {
  targetUrl: string;
  method: string;
  correctHooksSignatureComponents: string;
  correctHooksSignature: string;
  body: string;
  now: number;
}

const publicVerifyingKeySets = new Map<string, PublicVerifyingKeySet>();
const verifiers = new Map<string, Verifier>();

function ok<T>(output: T): ApiResponse<T> {
  return { output, error: null };
}

function fail<T>(error: string): ApiResponse<T> {
  return { output: null, error };
}

const app = new Hono();

app.get("/health", (c) => c.body(null, 200));

app.post("/generate_secret_signing_key", (c) => c.json(generateSecretSigningKey()));

app.post("/create_public_verifying_key_set", async (c) => {
  const request = await c.req.json<CreatePublicVerifyingKeySetRequest>();
  try {
    const result = createPublicVerifyingKeySet(request.keys);
    return c.json(ok(result));
  } catch (err) {
    if (err instanceof CreatePublicVerifyingKeySetError) {
      return c.json(fail(err.name));
    }
    throw err;
  }
});

app.post("/sign", async (c) => {
  const request = await c.req.json<SignRequest>();
  try {
    const body = decodeBase64(request.body);
    const result = sign({
      targetUrl: new URL(request.targetUrl),
      webhookId: request.webhookId,
      recipientId: request.recipientId,
      method: request.method,
      requestBody: body,
      secretSigningKey: request.signingKey,
    });
    return c.json(ok(result));
  } catch (err) {
    if (err instanceof SignError) {
      return c.json(fail(err.name));
    }
    throw err;
  }
});

app.post("/verify_with_time", async (c) => {
  const request = await c.req.json<VerifyWithTimeRequest>();
  try {
    const body = decodeBase64(request.body);
    const result = verifyWithTime(
      {
        targetUrl: new URL(request.targetUrl),
        method: request.method,
        correctHooksSignatureComponents: request.correctHooksSignatureComponents,
        correctHooksSignature: request.correctHooksSignature,
        requestBody: body,
      },
      request.recipientId,
      request.signatureTtlSeconds,
      request.publicVerifyingKeySet,
      request.now,
    );
    return c.json(ok(result));
  } catch (err) {
    if (err instanceof VerifyError) {
      return c.json(fail(err.name));
    }
    throw err;
  }
});

app.post("/register_public_verifying_key_set/:id", async (c) => {
  const request = await c.req.json<RegisterPublicVerifyingKeySetRequest>();
  const id = c.req.param("id");
  if (request.publicVerifyingKeySet) {
    publicVerifyingKeySets.set(id, request.publicVerifyingKeySet);
  } else {
    publicVerifyingKeySets.delete(id);
  }
  return c.body(null, 200);
});

app.get("/get_public_verifying_key_set/:id", (c) => {
  const id = c.req.param("id");
  const keySet = publicVerifyingKeySets.get(id);
  if (keySet === undefined) {
    return c.body(null, 404);
  }
  return c.json(keySet);
});

app.post("/register_new_verifier/:id", async (c) => {
  const request = await c.req.json<VerifierConfig>();
  const id = c.req.param("id");
  verifiers.set(id, new Verifier(request));
  return c.body(null, 200);
});

app.post("/verify_with_time_with_verifier/:id", async (c) => {
  const request = await c.req.json<VerifyWithTimeWithVerifierRequest>();
  const id = c.req.param("id");
  const verifier = verifiers.get(id);
  if (verifier === undefined) {
    console.error(`No verifier for id ${id}`);
    throw `No verifier for id ${id}`;
  }
  try {
    const body = decodeBase64(request.body);
    const result = await verifier.verifyWithTime(
      {
        targetUrl: new URL(request.targetUrl),
        method: request.method,
        correctHooksSignatureComponents: request.correctHooksSignatureComponents,
        correctHooksSignature: request.correctHooksSignature,
        requestBody: body,
      },
      request.now,
    );
    return c.json(ok(result));
  } catch (err) {
    console.error(err);
    if (err instanceof VerifyError) {
      return c.json(fail(err.name));
    }
    throw err;
  }
});

function parsePort(): number {
  const { values } = parseArgs({ options: { port: { type: "string" } } });
  const portString = values.port ?? process.env["TYPESCRIPT_CORRECT_HOOKS_TEST_SERVER_PORT"];
  const port = Number(portString);
  if (!port) {
    throw new Error(
      "Missing or invalid port: pass --port or set TYPESCRIPT_CORRECT_HOOKS_TEST_SERVER_PORT",
    );
  }
  return port;
}

serve({ fetch: app.fetch, port: parsePort(), hostname: "0.0.0.0" });
