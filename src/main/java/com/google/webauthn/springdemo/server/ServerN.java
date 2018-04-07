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
import com.google.webauthn.springdemo.crypto.AlgorithmIdentifierMapper;
import com.google.webauthn.springdemo.crypto.Crypto;
import com.google.webauthn.springdemo.entities.CredentialStoreN;
import com.google.webauthn.springdemo.entities.SessionDataN;
import com.google.webauthn.springdemo.exceptions.ResponseException;
import com.google.webauthn.springdemo.exceptions.WebAuthnException;
import com.google.webauthn.springdemo.objects.AuthenticatorAssertionResponseN;
import com.google.webauthn.springdemo.objects.AuthenticatorAttestationResponseN;
import com.google.webauthn.springdemo.objects.AuthenticatorResponseN;
import com.google.webauthn.springdemo.objects.EccKey;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialN;
import com.google.webauthn.springdemo.objects.RsaKey;
import com.google.webauthn.springdemo.services.CredentialStoreNService;
import com.google.webauthn.springdemo.services.SessionDataNService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.ServletException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.logging.Logger;

@Service
public class ServerN {

    private static final Logger Log = Logger.getLogger(ServerN.class.getName());

    final CredentialStoreNService credentialStoreNService;

    final SessionDataNService sessionDataNService;

    @Autowired
    public ServerN(
            CredentialStoreNService credentialStoreNService,
            SessionDataNService sessionDataNService) {

        this.credentialStoreNService = credentialStoreNService;
        this.sessionDataNService = sessionDataNService;
    }

    @Transactional(rollbackFor = Exception.class)
    public void verifySessionAndChallenge(
            final AuthenticatorResponseN assertionResponse,
            final Long userId,
            final String sessionId) throws ResponseException {

        Log.info("-- Verifying provided session and challenge data --");
        // TODO: when it's calling from an Android application via Endpoints API, the session ID
        // is temporarily null for now.
        if (sessionId == null) {
            return;
        }

        final long id;
        try {
            id = Long.valueOf(sessionId);
        } catch (NumberFormatException e) {
            throw new ResponseException("Provided session id invalid");
        }

        /* Invalidate old sessions */
        sessionDataNService.removeOldSessions(userId);

        final SessionDataN session = sessionDataNService.findByIdAndUserId(Long.valueOf(id), userId).orElse(null);
        if (session == null) {
            throw new ResponseException("Session invalid");
        }
        sessionDataNService.remove(Long.valueOf(id), userId);

        // Session.getChallenge is a base64-encoded string
        final byte[] sessionChallenge = Base64.getDecoder().decode(session.getChallenge());
        // assertionResponse.getClientData().getChallenge() is a base64url-encoded string
        final byte[] clientSessionChallenge = Base64.getUrlDecoder().decode(assertionResponse.getCollectedClientDataN().getChallenge());
        if (!Arrays.equals(sessionChallenge, clientSessionChallenge)) {
            throw new ResponseException("Returned challenge incorrect");
        }
        Log.info("Successfully verified session and challenge data");
    }

    public CredentialStoreN validateAndFindCredential(
            final PublicKeyCredentialN cred,
            final Long userId,
            final String sessionId) throws ResponseException {

        if (!(cred.getResponse() instanceof AuthenticatorAssertionResponseN)) {
            throw new ResponseException("Invalid authenticator response");
        }

        final AuthenticatorAssertionResponseN assertionResponse =
                (AuthenticatorAssertionResponseN) cred.getResponse();

        final Set<CredentialStoreN> savedCreds = credentialStoreNService.findByUserId(userId);
        if (savedCreds == null || savedCreds.size() == 0) {
            throw new ResponseException("No credentials registered for this user");
        }

        try {
            verifySessionAndChallenge(assertionResponse, userId, sessionId);
        } catch (ResponseException e1) {
            throw new ResponseException("Unable to verify session and challenge data");
        }

        CredentialStoreN credential = null;
        for (final CredentialStoreN saved : savedCreds) {
            if (saved.getPublicKeyCredentialId().equals(cred.getId())) {
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
        } catch (ResponseException | CborException e) {
            throw new ServletException("Stored attestation missing");
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
                throw new ServletException("Signature invalid");
            }
        } catch (WebAuthnException e) {
            throw new ServletException("Failure while verifying signature");
        }

        if (assertionResponse.getAuthenticatorData().getSignCount() <= savedCredential.getSignCount()) {
            throw new ServletException("Sign count invalid");
        }

        credentialStoreNService.updateSignCount(savedCredential, assertionResponse.getAuthenticatorData().getSignCount());

        Log.info("Signature verified");
    }

}
