import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
  UUID,
} from "node:crypto";

import { Buffer } from "node:buffer";
import { Mutex } from "async-mutex";

import * as uuid from "uuid";

/** The signature version produced by this version of the library. */
export const SIGNATURE_VERSION = "v1";
const DEFAULT_SIGNATURE_TTL_SECONDS = 300;
const DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS = 300;

const VALID_HTTP_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "DELETE",
  "CONNECT",
  "OPTIONS",
  "TRACE",
  "PATCH",
]);

/**
 * A key used to sign requests.
 *
 * Must be kept secret and should only be held by the signer.
 */
export interface SecretSigningKey {
  kid: string;
  kty: string;
  crv: string;
  x: string;
  d: string;
}

interface PublicJwk {
  kid: string;
  kty: string;
  crv: string;
  x: string;
}

/** A set of public keys used to verify signed requests. */
export interface PublicVerifyingKeySet {
  keys: PublicJwk[];
}

interface SignatureComponents {
  webhookId: string;
  targetUrl: URL;
  method: string;
  keyId: string;
  signedAt: number;
}

/** The possible error names of a {@link CreatePublicVerifyingKeySetError}. */
export type CreatePublicVerifyingKeySetErrorName = "InvalidKeyFound";

/** Errors that can be thrown from {@link createPublicVerifyingKeySet}. */
export class CreatePublicVerifyingKeySetError extends Error {
  constructor(override readonly name: CreatePublicVerifyingKeySetErrorName) {
    super(name);
  }
}

/** The arguments to the {@link sign} function. */
export interface SignArgs {
  /**
   * An id for the webhook.
   *
   * This id should be unique for the event triggering the webhook, and should
   * be reused for any delivery retries.
   */
  webhookId: string;
  /**
   * The url the webhook is being sent to.
   *
   * Must be the exact url provided by the webhook consumer.
   */
  targetUrl: URL;
  /** The HTTP method the webhook will be sent with. */
  method: string;
  /** The exact body of the webhook request as bytes. */
  requestBody: Uint8Array;
  /** The {@link SecretSigningKey} the signature will be signed with. */
  secretSigningKey: SecretSigningKey;
}

/** Header values to set on the webhook request.
 *
 *  You must set the request headers `correct-hooks-signature-components` and `correct-hooks-signature` to these values.
 *  Webhook consumers will pass the values of the headers to the verify function. Future versions of Correct Hooks with
 *  convenience functions that verify specific framework's request objects will expect these exact header names to be set.
 */
export interface SignatureData {
  /** Set the header `correct-hooks-signature-components` to this value. */
  correctHooksSignatureComponents: string;
  /** Set the header `correct-hooks-signature` to this value. */
  correctHooksSignature: string;
}

/** The possible error names of a {@link SignError}. */
export type SignErrorName = "InvalidArgs" | "InvalidSigningKey";

/** Errors thrown by the {@link sign} function. */
export class SignError extends Error {
  constructor(override readonly name: SignErrorName) {
    super(name);
  }
}

/** The arguments to {@link Verifier.verify} and {@link Verifier.verifyWithTime}. */
export interface VerifyArgs {
  /**
   * The url your endpoint is receiving requests at.
   *
   * `targetUrl` needs to be the exact url given to the webhook provider,
   * preferably retrieved from an environment variable or hardcoded.
   */
  targetUrl: URL;
  /** The HTTP method the request was sent with. Can be extracted from the request. */
  method: string;
  /** The value from the request's `correct-hooks-signature-components` header. */
  correctHooksSignatureComponents: string;
  /** The value from the request's `correct-hooks-signature` header. */
  correctHooksSignature: string;
  /** The unparsed request body as bytes. */
  requestBody: Uint8Array;
}

/** Validated request data. */
export interface VerifiedData {
  /**
   * The validated `webhookId` for the request. These id's can be put in a shared cache
   * by the webhook consumer and checked against for the highest level of replay protection.
   */
  webhookId: string;
}

/**
 * The possible error names of a {@link VerifyError}.
 *
 * - `PublicVerifyingKeyNotFound`: The key needed to verify the request was not found in the
 *   verifying key set provided by the webhook provider. If you receive this error consistently,
 *   the webhook provider may need to update their published public verifying key set. In some
 *   specific cases, this error can also be returned due to an invalid signature.
 * - `PublicVerifyingKeyRetrievalFailed`: The webhook provider's public verifying key set could
 *   not be retrieved. If you get this error, likely either the `publicVerifyingKeySetUrl` the
 *   {@link Verifier} was created with is incorrect, or the webhook producer's endpoint is
 *   unavailable.
 * - `InvalidSignature`: The request's signature is invalid.
 * - `InvalidPublicVerifyingKey`: The public verifying key set retrieved from
 *   `publicVerifyingKeySetUrl` could not be parsed and likely needs to be updated by the
 *   webhook producer.
 */
export type VerifyErrorName =
  | "PublicVerifyingKeyNotFound"
  | "PublicVerifyingKeyRetrievalFailed"
  | "InvalidSignature"
  | "InvalidPublicVerifyingKey";

/**
 * Errors thrown by {@link Verifier.verify}. Receiving any error from {@link Verifier.verify} indicates that the
 * request is invalid and should be rejected with a 4xx error code.
 */
export class VerifyError extends Error {
  constructor(override readonly name: VerifyErrorName) {
    super(name);
  }
}

/** Generate a new {@link SecretSigningKey}. */
export function generateSecretSigningKey(): SecretSigningKey {
  const keyId = randomUUID();
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  if (
    jwk.kty === undefined ||
    jwk.crv === undefined ||
    jwk.x === undefined ||
    jwk.d === undefined
  ) {
    throw new Error("Internal CorrectHooks error");
  }

  return {
    kid: keyId,
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    d: jwk.d,
  };
}

/**
 * Creates a {@link PublicVerifyingKeySet} from a list of {@link SecretSigningKey}.
 *
 * The returned {@link PublicVerifyingKeySet} can be used to verify requests signed
 * by any of the `secretSigningKeys`.
 *
 * @throws {@link CreatePublicVerifyingKeySetError} if any of the keys is invalid.
 */
export function createPublicVerifyingKeySet(
  secretSigningKeys: readonly SecretSigningKey[],
): PublicVerifyingKeySet {
  const publicJwks: PublicVerifyingKeySet = { keys: [] };
  for (const privateKeyJwk of secretSigningKeys) {
    const kid = privateKeyJwk.kid;
    let x: string | undefined;
    try {
      const privateKey = createPrivateKey({
        key: { kty: "OKP", crv: "Ed25519", x: privateKeyJwk.x, d: privateKeyJwk.d },
        format: "jwk",
      });
      const publicKey = createPublicKey(privateKey);
      x = publicKey.export({ format: "jwk" }).x;
    } catch {
      throw new CreatePublicVerifyingKeySetError("InvalidKeyFound");
    }

    if (x === undefined) {
      throw new Error("Internal CorrectHooks error");
    }
    publicJwks.keys.push({ kty: "OKP", crv: "Ed25519", kid, x });
  }
  return publicJwks;
}

/**
 * Creates a signature for a webhook request and returns the signature headers that should be set on the request.
 *
 * You must set the request headers `correct-hooks-signature-components` and `correct-hooks-signature` to these values.
 * Webhook consumers will pass the values of the headers to the verify function. Future versions of Correct Hooks with
 * convenience functions that verify specific framework's request objects will expect these exact header names to be set.
 *
 * `sign` should be called every time a webhook delivery is attempted. The signed headers should not be reused
 * between retried delivery attempts.
 *
 * @throws {@link SignError} if the method or signing key is invalid.
 */
export function sign(args: SignArgs): SignatureData {
  const { webhookId, targetUrl, method, requestBody, secretSigningKey } = args;

  if (!uuid.validate(webhookId) || uuid.version(webhookId) !== 4) {
    throw new SignError("InvalidArgs")
  }

  try {
    new URL(targetUrl)
  } catch {
    throw new SignError("InvalidArgs")
  }

  if (!isValidHttpMethod(method)) {
    throw new SignError("InvalidArgs");
  }

  const keyId = secretSigningKey.kid;
  const signedAt = secondsSinceUnixEpoch();

  const signatureComponents: SignatureComponents = {
    webhookId,
    targetUrl,
    method,
    keyId,
    signedAt,
  };

  const encodedSignatureComponents = encodeSignatureComponents(signatureComponents);
  const signatureComponentsHeader = versionHeaderValue(encodedSignatureComponents);

  let signingKey: KeyObject;
  try {
    signingKey = createPrivateKey({
      key: { kty: "OKP", crv: "Ed25519", x: secretSigningKey.x, d: secretSigningKey.d },
      format: "jwk",
    });
  } catch {
    throw new SignError("InvalidSigningKey");
  }
  const signatureMessage = constructSignatureMessage(signatureComponents, Buffer.from(requestBody));

  const signature = cryptoSign(null, signatureMessage, signingKey);
  const signatureBase64 = encodeBase64(signature);
  const signatureHeaderValue = versionHeaderValue(signatureBase64);

  return {
    correctHooksSignatureComponents: signatureComponentsHeader,
    correctHooksSignature: signatureHeaderValue,
  };
}

/** Arguments for creating a {@link Verifier}. */
export interface VerifierConfig {
  /**
   * The url serving the webhook provider's verifying key set.
   *
   * The webhook provider should give you this url.
   */
  publicVerifyingKeySetUrl: URL;
  /**
   * How long a signature is considered valid. Defaults to 300 seconds (5 minutes).
   *
   * In most cases, the default parameter should be used.
   * This parameter should not be set to a value larger than 300 (may be enforced in the future).
   */
  signatureTtlSeconds?: number;
  /**
   * How long a retrieved `publicVerifyingKeySet` can be used before it is considered stale. Defaults to 300 seconds (5 minutes).
   *
   * In most cases, the default parameter should be used.
   * This parameter should not be set to a value larger than 300 (may be enforced in the future).
   */
  publicVerifyingKeySetTtlSeconds?: number;
}

/**
 * Verifier for signed webhook requests
 *
 * The {@link Verifier} handles retrieving and refreshing the webhook producer's verifying key set for you.
 *
 * Ideally you should create one {@link Verifier} when your backend instance starts and reuse it for all requests sent to that backend instance.
 */
export class Verifier {
  private readonly publicVerifyingKeySetUrl: URL;
  private readonly signatureTtlSeconds: number;
  private readonly publicVerifyingKeySetTtlSeconds: number;
  private publicVerifyingKeySet: PublicVerifyingKeySet;
  private publicVerifyingKeySetRefreshedAt: number;
  private publicVerifyingKeySetRefreshId: string;
  private publicVerifyingKeySetRefreshLock: Mutex;

  /** Create a new {@link Verifier}. */
  constructor(config: VerifierConfig) {
    this.publicVerifyingKeySetUrl = config.publicVerifyingKeySetUrl;
    this.signatureTtlSeconds = config.signatureTtlSeconds ?? DEFAULT_SIGNATURE_TTL_SECONDS;
    this.publicVerifyingKeySetTtlSeconds =
      config.publicVerifyingKeySetTtlSeconds ?? DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS;
    this.publicVerifyingKeySet = { keys: [] };
    this.publicVerifyingKeySetRefreshedAt = 0;
    this.publicVerifyingKeySetRefreshId = randomUUID();
    this.publicVerifyingKeySetRefreshLock = new Mutex();
  }

  /**
   * Verifies a request and returns validated information from the Correct Hooks request headers.
   *
   * This function confirms that the provided request signature is valid, that the signature has not expired, and that the request was sent to the intended endpoint.
   *
   * @throws {@link VerifyError} Any thrown error indicates that the signature could not be verified and the request should be rejected with a 4xx error.
   */
  async verify(args: VerifyArgs): Promise<VerifiedData | undefined> {
    const now = secondsSinceUnixEpoch();
    return await this.verifyWithTime(args, now);
  }

  /**
   * The same as {@link Verifier.verify} but with the current time provided by the caller, which
   * can be useful for testing.
   *
   * @param args - The request data to verify.
   * @param now - The current time in seconds since Unix epoch.
   */
  async verifyWithTime(args: VerifyArgs, now: number): Promise<VerifiedData | undefined> {
    if (now > this.publicVerifyingKeySetRefreshedAt + this.publicVerifyingKeySetTtlSeconds) {
      try {
        await this.refreshJwks(this.publicVerifyingKeySetRefreshId);
      } catch {}
    }
    try {
      return verifyWithTime(args, this.signatureTtlSeconds, this.publicVerifyingKeySet, now);
    } catch (error) {
      if (!(error instanceof VerifyError && error.name === "PublicVerifyingKeyNotFound")) {
        throw error;
      }
    }

    try {
      await this.refreshJwks(this.publicVerifyingKeySetRefreshId);
    } catch {
      throw new VerifyError("PublicVerifyingKeyRetrievalFailed");
    }

    return verifyWithTime(args, this.signatureTtlSeconds, this.publicVerifyingKeySet, now);
  }

  private async refreshJwks(oldRefreshId: string): Promise<void> {
    const release = await this.publicVerifyingKeySetRefreshLock.acquire();
    try {
      if (this.publicVerifyingKeySetRefreshId != oldRefreshId) {
        return;
      }
      const new_refresh_time = secondsSinceUnixEpoch();
      let response: Response;

      response = await fetch(this.publicVerifyingKeySetUrl);
      if (response.status !== 200) {
        throw new VerifyError("PublicVerifyingKeyRetrievalFailed");
      }
      let keySet = (await response.json()) as PublicVerifyingKeySet;
      this.publicVerifyingKeySet = keySet;
      this.publicVerifyingKeySetRefreshedAt = new_refresh_time;
    } finally {
      release();
    }
  }
}

/**
 * This function is only public for internal testing purposes and will be made private in a future version of this library.
 */
export function verifyWithTime(
  args: VerifyArgs,
  signatureTtlSeconds: number,
  publicVerifyingKeySet: PublicVerifyingKeySet,
  now: number,
): VerifiedData {
  const { targetUrl, method, correctHooksSignatureComponents, correctHooksSignature, requestBody } =
    args;

  const encodedSignatureComponents = splitVersionedHeader(correctHooksSignatureComponents).get(
    SIGNATURE_VERSION,
  );
  if (encodedSignatureComponents === undefined) {
    throw new VerifyError("InvalidSignature");
  }
  let signatureComponents: SignatureComponents;
  try {
    signatureComponents = decodeSignatureComponents(encodedSignatureComponents);
  } catch {
    throw new VerifyError("InvalidSignature");
  }

  const verifyingKeyJwk = publicVerifyingKeySet.keys.find(
    (key) => key.kid.toLowerCase() === signatureComponents.keyId.toLowerCase(),
  );
  if (verifyingKeyJwk === undefined) {
    throw new VerifyError("PublicVerifyingKeyNotFound");
  }

  let verifyingKey: KeyObject;
  try {
    verifyingKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: verifyingKeyJwk.x },
      format: "jwk",
    });
  } catch {
    throw new VerifyError("InvalidPublicVerifyingKey");
  }

  const signatureMessage = constructSignatureMessage(signatureComponents, Buffer.from(requestBody));
  const signatureEncoded = splitVersionedHeader(correctHooksSignature).get(SIGNATURE_VERSION);
  if (signatureEncoded === undefined) {
    throw new VerifyError("InvalidSignature");
  }

  let signatureBytes: Buffer;
  try {
    signatureBytes = decodeBase64(signatureEncoded);
  } catch {
    throw new VerifyError("InvalidSignature");
  }

  let signatureIsValid: boolean;
  try {
    signatureIsValid = cryptoVerify(null, signatureMessage, verifyingKey, signatureBytes);
  } catch {
    throw new VerifyError("InvalidSignature");
  }

  if (!signatureIsValid) {
    throw new VerifyError("InvalidSignature");
  }

  if (targetUrl.toString() !== signatureComponents.targetUrl.toString()) {
    throw new VerifyError("InvalidSignature");
  }

  if (method !== signatureComponents.method) {
    throw new VerifyError("InvalidSignature");
  }

  if (
    now > signatureComponents.signedAt + signatureTtlSeconds ||
    now + signatureTtlSeconds < signatureComponents.signedAt
  ) {
    throw new VerifyError("InvalidSignature");
  }

  return { webhookId: signatureComponents.webhookId };
}

function constructSignatureMessage(
  signatureComponents: SignatureComponents,
  requestBody: Buffer,
): Buffer {
  const encoded_signature_components = encodeSignatureComponents(signatureComponents);
  const signatureComponentsBytes = Buffer.from(`${encoded_signature_components}.`, "utf-8");
  return Buffer.concat([signatureComponentsBytes, requestBody]);
}

function versionHeaderValue(headerValue: string): string {
  return `${SIGNATURE_VERSION},${headerValue}`;
}

function splitVersionedHeader(header: string): Map<string, string> {
  const splitHeaders = new Map<string, string>();
  for (const versionedValue of header.split(" ")) {
    const [version, value] = versionedValue.split(",");
    if (version === undefined || value === undefined) {
      continue;
    }
    splitHeaders.set(version, value);
  }
  return splitHeaders;
}

function encodeSignatureComponents(signatureComponents: SignatureComponents): string {
  const webhookIdBase64 = encodeBase64FromString(signatureComponents.webhookId);
  const targetUrlBase64 = encodeBase64FromString(signatureComponents.targetUrl.toString());
  const methodBase64 = encodeBase64FromString(signatureComponents.method);
  const keyIdBase64 = encodeBase64FromString(signatureComponents.keyId.toString());
  const signedAtBase64 = encodeBase64FromString(signatureComponents.signedAt.toString());

  const encodedSignatureComponents = `${webhookIdBase64}.${targetUrlBase64}.${methodBase64}.${keyIdBase64}.${signedAtBase64}`;
  return encodedSignatureComponents;
}

function decodeSignatureComponents(encodedSignatureComponents: string): SignatureComponents {
  const components = encodedSignatureComponents.split(".");
  if (components.length != 5) {
    throw "Invalid component count";
  }
  const webhookId = decodeBase64ToString(components[0] as string);
  const targetUrl = new URL(decodeBase64ToString(components[1] as string));
  const method = decodeBase64ToString(components[2] as string);
  const keyId = decodeBase64ToString(components[3] as string) as UUID;
  const signedAt = parseInt(decodeBase64ToString(components[4] as string));
  const signatureComponents = { webhookId, targetUrl, method, keyId, signedAt };
  return signatureComponents;
}

function encodeBase64(bytes: Buffer): string {
  return bytes.toString("base64url");
}

function isValidHttpMethod(method: string): boolean {
  return VALID_HTTP_METHODS.has(method);
}

/**
 * This function is only public for internal testing purposes and will be made private in a future version of this library.
 */
export function decodeBase64(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

function encodeBase64FromString(data: string): string {
  return encodeBase64(Buffer.from(data, "utf-8"));
}

function decodeBase64ToString(base64_string: string): string {
  return decodeBase64(base64_string).toString("utf-8");
}

function secondsSinceUnixEpoch(): number {
  return Math.floor(Date.now() / 1000);
}
