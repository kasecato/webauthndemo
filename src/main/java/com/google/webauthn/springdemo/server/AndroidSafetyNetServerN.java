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

package com.google.webauthn.springdemo.server;

import co.nstant.in.cbor.CborException;
import com.google.common.primitives.Bytes;
import com.google.webauthn.springdemo.crypto.Crypto;
import com.google.webauthn.springdemo.crypto.OfflineVerify;
import com.google.webauthn.springdemo.crypto.OfflineVerify.AttestationStatement;
import com.google.webauthn.springdemo.entities.CredentialStoreN;
import com.google.webauthn.springdemo.exceptions.ResponseException;
import com.google.webauthn.springdemo.exceptions.WebAuthnException;
import com.google.webauthn.springdemo.objects.AndroidSafetyNetAttestationStatement;
import com.google.webauthn.springdemo.objects.AuthenticatorAssertionResponseN;
import com.google.webauthn.springdemo.objects.AuthenticatorAttestationResponseN;
import com.google.webauthn.springdemo.objects.EccKey;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialN;
import com.google.webauthn.springdemo.services.CredentialStoreNService;
import com.google.webauthn.springdemo.services.SessionDataNService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.ServletException;
import java.util.Arrays;
import java.util.Set;
import java.util.logging.Logger;

@Service
public class AndroidSafetyNetServerN extends ServerN {

    private static final Logger Log = Logger.getLogger(AndroidSafetyNetServerN.class.getName());

    @Autowired
    public AndroidSafetyNetServerN(
            final CredentialStoreNService credentialStoreNService,
            final SessionDataNService sessionDataNService) {

        super(credentialStoreNService, sessionDataNService);
    }

    @Transactional(rollbackFor = Exception.class)
    public void registerCredential(
            final PublicKeyCredentialN cred,
            final Long userId,
            final String session,
            final String rpId) throws ServletException {

        if (!(cred.getResponse() instanceof AuthenticatorAttestationResponseN)) {
            throw new ServletException("Invalid response structure");
        }

        final AuthenticatorAttestationResponseN attResponse =
                (AuthenticatorAttestationResponseN) cred.getResponse();

        final Set<CredentialStoreN> savedCreds = credentialStoreNService.findByUserId(userId);
        for (final CredentialStoreN c : savedCreds) {
            if (c.getPublicKeyCredentialId().equals(cred.getId())) {
                throw new ServletException("Credential already registerd for this user");
            }
        }

        try {
            verifySessionAndChallenge(attResponse, userId, session);
        } catch (final ResponseException e1) {
            throw new ServletException("Unable to verify session and challenge data");
        }

        final AndroidSafetyNetAttestationStatement attStmt =
                (AndroidSafetyNetAttestationStatement) attResponse.getAttestationObject().getAttStmt();

        final AttestationStatement stmt = OfflineVerify.parseAndVerify(new String(attStmt.getResponse()));
        if (stmt == null) {
            Log.info("Failure: Failed to parse and verify the attestation statement.");
            throw new ServletException("Failed to verify attestation statement");
        }

        final byte[] clientDataHash = Crypto.sha256Digest(attResponse.getClientDataBytes());

        try {
            final byte[] expectedNonce = Bytes.concat(attResponse.getAttestationObject().getAuthData().encode(), clientDataHash);
            if (!Arrays.equals(expectedNonce, stmt.getNonce())) {
                throw new ServletException("Nonce does not match");
            }
        } catch (final CborException e) {
            throw new ServletException("Error encoding authdata");
        }

        /*
         * // Test devices won't pass this. if (!stmt.isCtsProfileMatch()) { throw new
         * ServletException("No cts profile match"); }
         */
    }

    // TODO Remove after switch to generic verification
    @Override
    @Transactional(rollbackFor = Exception.class)
    public void verifyAssertion(
            final PublicKeyCredentialN cred,
            final Long userId,
            final String sessionId,
            final CredentialStoreN savedCredential) throws ServletException {

        final AuthenticatorAssertionResponseN assertionResponse =
                (AuthenticatorAssertionResponseN) cred.getResponse();

        Log.info("-- Verifying signature --");
        final AuthenticatorAttestationResponseN storedAttData;
        try {
            storedAttData = new AuthenticatorAttestationResponseN(savedCredential.getAttestationObjectBytes());
        } catch (final ResponseException | CborException e) {
            throw new ServletException("Stored attestation missing");
        }

        if (!(storedAttData.getAttestationObject().getAuthData().getAttData()
                .getPublicKey() instanceof EccKey)) {
            throw new ServletException("Ecc key not provided");
        }

        final EccKey publicKey = (EccKey) storedAttData.getAttestationObject().getAuthData().getAttData().getPublicKey();
        try {
            final byte[] clientDataHash = Crypto.sha256Digest(assertionResponse.getClientDataBytes());
            final byte[] signedBytes = Bytes.concat(assertionResponse.getAuthenticatorData().encode(), clientDataHash);
            if (!Crypto.verifySignature(Crypto.decodePublicKey(publicKey.getX(), publicKey.getY()),
                    signedBytes, assertionResponse.getSignatureBytes())) {
                throw new ServletException("Signature invalid");
            }
        } catch (final WebAuthnException e) {
            throw new ServletException("Failure while verifying signature", e);
        } catch (final CborException e) {
            throw new ServletException("Failure while verifying authenticator data");
        }

        if (assertionResponse.getAuthenticatorData().getSignCount() <= savedCredential.getSignCount()
                && savedCredential.getSignCount() != 0) {
            throw new ServletException("Sign count invalid");
        }

        credentialStoreNService.updateSignCount(savedCredential, assertionResponse.getAuthenticatorData().getSignCount());

        Log.info("Signature verified");
    }

}
