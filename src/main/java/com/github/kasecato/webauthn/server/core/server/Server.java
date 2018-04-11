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
import com.github.kasecato.webauthn.server.core.crypto.AlgorithmIdentifierMapper;
import com.github.kasecato.webauthn.server.core.crypto.Crypto;
import com.github.kasecato.webauthn.server.core.exceptions.ResponseException;
import com.github.kasecato.webauthn.server.core.exceptions.SignatureException;
import com.github.kasecato.webauthn.server.core.exceptions.WebAuthnException;
import com.github.kasecato.webauthn.server.core.models.CredentialModel;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorAssertionResponse;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorAttestationResponse;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorResponse;
import com.github.kasecato.webauthn.server.core.objects.EccKey;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredential;
import com.github.kasecato.webauthn.server.core.objects.RsaKey;
import com.google.common.primitives.Bytes;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.logging.Logger;

public class Server {

    private static final Logger Log = Logger.getLogger(Server.class.getName());

    public static void verifySessionAndChallenge(
            final AuthenticatorResponse assertionResponse,
            final String savedChallengeBase64Encoded)
            throws ResponseException {

        Log.info("-- Verifying provided session and challenge data --");

        if (savedChallengeBase64Encoded == null) {
            return;
        }

        // Session.getChallenge is a base64-encoded string
        final byte[] sessionChallenge = Base64.getDecoder().decode(savedChallengeBase64Encoded);
        // assertionResponse.getClientData().getChallenge() is a base64url-encoded string
        final byte[] clientSessionChallenge = Base64.getUrlDecoder().decode(assertionResponse.getCollectedClientData().getChallenge());
        if (!Arrays.equals(sessionChallenge, clientSessionChallenge)) {
            throw new ResponseException("Returned challenge incorrect");
        }
        Log.info("Successfully verified session and challenge data");
    }

    public static CredentialModel validateAndFindCredential(
            final PublicKeyCredential cred,
            final String savedChallengeBase64Encoded,
            final Collection<CredentialModel> savedCredentials)
            throws ResponseException {

        if (!(cred.getResponse() instanceof AuthenticatorAssertionResponse)) {
            throw new ResponseException("Invalid authenticator response");
        }

        final AuthenticatorAssertionResponse assertionResponse =
                (AuthenticatorAssertionResponse) cred.getResponse();

        try {
            verifySessionAndChallenge(assertionResponse, savedChallengeBase64Encoded);
        } catch (final ResponseException e1) {
            throw new ResponseException("Unable to verify session and challenge data");
        }

        CredentialModel credential = null;
        for (final CredentialModel saved : savedCredentials) {
            if (saved.getId().equals(cred.getId())) {
                credential = saved;
                break;
            }
        }

        if (credential == null) {
            Log.info("Credential not registered with this user");
            throw new ResponseException("Received response from credential not associated with user");
        }

        return credential;
    }

    public int verifyAssertion(
            final PublicKeyCredential cred,
            final CredentialModel savedCred)
            throws WebAuthnException, SignatureException {

        final AuthenticatorAssertionResponse assertionResponse =
                (AuthenticatorAssertionResponse) cred.getResponse();

        Log.info("-- Verifying signature --");
        final AuthenticatorAttestationResponse storedAttData;
        try {
            storedAttData = new AuthenticatorAttestationResponse(savedCred.getAttestationObjectBytes());
        } catch (final ResponseException | CborException e) {
            throw new WebAuthnException("Stored attestation missing");
        }

        try {
            final PublicKey publicKey;
            if (storedAttData.getAttestationObject().getAuthData().getAttData()
                    .getPublicKey() instanceof EccKey) {
                publicKey = Crypto.getECPublicKey((EccKey) storedAttData.getAttestationObject()
                        .getAuthData().getAttData().getPublicKey());
            } else {
                publicKey = Crypto.getRSAPublicKey((RsaKey) storedAttData.getAttestationObject()
                        .getAuthData().getAttData().getPublicKey());
            }

            final byte[] clientDataHash = Crypto.sha256Digest(assertionResponse.getClientDataBytes());

            // concat of aData (authDataBytes) and hash of cData (clientDataHash)
            final byte[] signedBytes = Bytes.concat(assertionResponse.getAuthenticatorDataBytes(), clientDataHash);
            final String signatureAlgorithm = AlgorithmIdentifierMapper.get(
                    storedAttData.getAttestationObject().getAuthData().getAttData().getPublicKey().getAlg())
                    .getJavaAlgorithm();
            if (!Crypto.verifySignature(publicKey, signedBytes, assertionResponse.getSignatureBytes(),
                    signatureAlgorithm)) {
                throw new SignatureException("Signature invalid");
            }
        } catch (final WebAuthnException e) {
            throw new WebAuthnException("Failure while verifying signature");
        }

        if (Integer.compareUnsigned(assertionResponse.getAuthenticatorData().getSignCount(), savedCred.getSignCount()) <= 0) {
            throw new WebAuthnException("Sign count invalid");
        }

        Log.info("Signature verified");

        return assertionResponse.getAuthenticatorData().getSignCount();
    }

}
