// The vault core's passkeys, checked by a verifier it shares no code with:
// the frozen registration and sign-in in the core's vectors
// (crates/vault-core/fixtures/vectors-passkeys.json), read as a site's
// server reads them, with @simplewebauthn/server.

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";

const vectors = JSON.parse(
  readFileSync(new URL("../../../crates/vault-core/fixtures/vectors-passkeys.json", import.meta.url), "utf8"),
);

const base64url = (hex: string) => Buffer.from(hex, "hex").toString("base64url");

test("a passkey the core makes registers, and signs in with the key registered", async () => {
  const { inputs, registration, sign_in } = vectors;
  const registered = await verifyRegistrationResponse({
    response: JSON.parse(registration.response_json) as RegistrationResponseJSON,
    expectedChallenge: base64url(inputs.registration_challenge),
    expectedOrigin: inputs.origin,
    expectedRPID: inputs.rp_id,
    requireUserVerification: true,
    supportedAlgorithmIDs: [-7],
  });
  assert.equal(registered.verified, true);
  const info = registered.registrationInfo!;
  assert.equal(info.fmt, "none");
  assert.equal(info.credential.id, base64url(inputs.credential_id));
  assert.equal(info.credential.counter, 0);
  assert.equal(info.userVerified, true);
  // It syncs: backup eligible, and backed up.
  assert.equal(info.credentialDeviceType, "multiDevice");
  assert.equal(info.credentialBackedUp, true);
  assert.equal(info.aaguid, "00000000-0000-0000-0000-000000000000");

  const signedIn = await verifyAuthenticationResponse({
    response: JSON.parse(sign_in.response_json) as AuthenticationResponseJSON,
    expectedChallenge: base64url(inputs.sign_in_challenge),
    expectedOrigin: inputs.origin,
    expectedRPID: inputs.rp_id,
    credential: info.credential,
    requireUserVerification: true,
  });
  assert.equal(signedIn.verified, true);
  assert.equal(signedIn.authenticationInfo.newCounter, 0);
  assert.equal(signedIn.authenticationInfo.userVerified, true);

  // Signed for another site, or another challenge, it is refused.
  await assert.rejects(
    verifyAuthenticationResponse({
      response: JSON.parse(sign_in.response_json) as AuthenticationResponseJSON,
      expectedChallenge: base64url(inputs.sign_in_challenge),
      expectedOrigin: inputs.origin,
      expectedRPID: "other.test",
      credential: info.credential,
    }),
  );
  await assert.rejects(
    verifyAuthenticationResponse({
      response: JSON.parse(sign_in.response_json) as AuthenticationResponseJSON,
      expectedChallenge: base64url(inputs.registration_challenge),
      expectedOrigin: inputs.origin,
      expectedRPID: inputs.rp_id,
      credential: info.credential,
    }),
  );
});
