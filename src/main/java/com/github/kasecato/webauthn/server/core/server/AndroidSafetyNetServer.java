// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.github.kasecato.webauthn.server.core.server;

import co.nstant.in.cbor.CborException;
import com.github.kasecato.webauthn.server.core.crypto.Crypto;
import com.github.kasecato.webauthn.server.core.crypto.OfflineVerify;
import com.github.kasecato.webauthn.server.core.crypto.OfflineVerify.AttestationStatement;
import com.github.kasecato.webauthn.server.core.exceptions.ResponseException;
import com.github.kasecato.webauthn.server.core.exceptions.SignatureException;
import com.github.kasecato.webauthn.server.core.exceptions.WebAuthnException;
import com.github.kasecato.webauthn.server.core.models.CredentialModel;
import com.github.kasecato.webauthn.server.core.objects.AndroidSafetyNetAttestationStatement;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorAssertionResponse;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorAttestationResponse;
import com.github.kasecato.webauthn.server.core.objects.EccKey;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredential;
import com.google.common.primitives.Bytes;

import java.util.Arrays;
import java.util.Collection;
import java.util.logging.Logger;

public class AndroidSafetyNetServer extends Server {

    private static final Logger Log = Logger.getLogger(AndroidSafetyNetServer.class.getName());

    public static void registerCredential(
            final PublicKeyCredential cred,
            final String savedChallengeBase64Encoded,
            final Collection<CredentialModel> savedCredentials,
            final String rpId)
            throws WebAuthnException, SignatureException {

        if (!(cred.getResponse() instanceof AuthenticatorAttestationResponse)) {
            throw new WebAuthnException("Invalid response structure");
        }

        final AuthenticatorAttestationResponse attResponse =
                (AuthenticatorAttestationResponse) cred.getResponse();

        for (final CredentialModel c : savedCredentials) {
            if (c.getId().equals(cred.getId())) {
                throw new WebAuthnException("Credential already registerd for this user");
            }
        }

        try {
            verifySessionAndChallenge(attResponse, savedChallengeBase64Encoded);
        } catch (final ResponseException e1) {
            throw new WebAuthnException("Unable to verify session and challenge data");
        }

        final AndroidSafetyNetAttestationStatement attStmt =
                (AndroidSafetyNetAttestationStatement) attResponse.getAttestationObject().getAttStmt();

        final AttestationStatement stmt = OfflineVerify.parseAndVerify(new String(attStmt.getResponse()));
        if (stmt == null) {
            Log.info("Failure: Failed to parse and verify the attestation statement.");
            throw new WebAuthnException("Failed to verify attestation statement");
        }

        final byte[] clientDataHash = Crypto.sha256Digest(attResponse.getClientDataBytes());

        try {
            final byte[] expectedNonce = Bytes.concat(attResponse.getAttestationObject().getAuthData().encode(), clientDataHash);
            if (!Arrays.equals(expectedNonce, stmt.getNonce())) {
                throw new SignatureException("Nonce does not match");
            }
        } catch (final CborException e) {
            throw new WebAuthnException("Error encoding authdata");
        }

        /*
         * // Test devices won't pass this. if (!stmt.isCtsProfileMatch()) { throw new
         * ServletException("No cts profile match"); }
         */
    }

    // TODO Remove after switch to generic verification
    @Override
    public int verifyAssertion(
            final PublicKeyCredential cred,
            final CredentialModel savedCredential)
            throws WebAuthnException, SignatureException {

        final AuthenticatorAssertionResponse assertionResponse =
                (AuthenticatorAssertionResponse) cred.getResponse();

        Log.info("-- Verifying signature --");
        final AuthenticatorAttestationResponse storedAttData;
        try {
            storedAttData = new AuthenticatorAttestationResponse(savedCredential.getAttestationObjectBytes());
        } catch (final ResponseException | CborException e) {
            throw new WebAuthnException("Stored attestation missing");
        }

        if (!(storedAttData.getAttestationObject().getAuthData().getAttData()
                .getPublicKey() instanceof EccKey)) {
            throw new WebAuthnException("Ecc key not provided");
        }

        final EccKey publicKey = (EccKey) storedAttData.getAttestationObject().getAuthData().getAttData().getPublicKey();
        try {
            final byte[] clientDataHash = Crypto.sha256Digest(assertionResponse.getClientDataBytes());
            final byte[] signedBytes = Bytes.concat(assertionResponse.getAuthenticatorData().encode(), clientDataHash);
            if (!Crypto.verifySignature(Crypto.decodePublicKey(publicKey.getX(), publicKey.getY()),
                    signedBytes, assertionResponse.getSignatureBytes())) {
                throw new SignatureException("Signature invalid");
            }
        } catch (final WebAuthnException e) {
            throw new WebAuthnException("Failure while verifying signature", e);
        } catch (final CborException e) {
            throw new WebAuthnException("Failure while verifying authenticator data");
        }

        if (Integer.compareUnsigned(assertionResponse.getAuthenticatorData().getSignCount(), savedCredential.getSignCount()) <= 0
                && savedCredential.getSignCount() != 0) {
            throw new WebAuthnException("Sign count invalid");
        }

        Log.info("Signature verified");

        return assertionResponse.getAuthenticatorData().getSignCount();
    }

}
