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
import com.google.webauthn.springdemo.entities.CredentialStore;
import com.google.webauthn.springdemo.entities.SessionData;
import com.google.webauthn.springdemo.exceptions.ResponseException;
import com.google.webauthn.springdemo.exceptions.WebAuthnException;
import com.google.webauthn.springdemo.objects.AuthenticatorAssertionResponse;
import com.google.webauthn.springdemo.objects.AuthenticatorAttestationResponse;
import com.google.webauthn.springdemo.objects.AuthenticatorResponse;
import com.google.webauthn.springdemo.objects.EccKey;
import com.google.webauthn.springdemo.objects.PublicKeyCredential;
import com.google.webauthn.springdemo.objects.RsaKey;
import com.google.webauthn.springdemo.services.CredentialStoreService;
import com.google.webauthn.springdemo.services.SessionDataService;
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
public class Server {

    private static final Logger Log = Logger.getLogger(Server.class.getName());

    final CredentialStoreService credentialStoreService;

    final SessionDataService sessionDataService;

    @Autowired
    public Server(
            CredentialStoreService credentialStoreService,
            SessionDataService sessionDataService) {

        this.credentialStoreService = credentialStoreService;
        this.sessionDataService = sessionDataService;
    }

    @Transactional(rollbackFor = Exception.class)
    public void verifySessionAndChallenge(
            final AuthenticatorResponse assertionResponse,
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
        sessionDataService.removeOldSessions(userId);

        final SessionData session = sessionDataService.findByIdAndUserId(Long.valueOf(id), userId).orElse(null);
        if (session == null) {
            throw new ResponseException("Session invalid");
        }
        sessionDataService.remove(Long.valueOf(id), userId);

        // Session.getChallenge is a base64-encoded string
        final byte[] sessionChallenge = Base64.getDecoder().decode(session.getChallenge());
        // assertionResponse.getClientData().getChallenge() is a base64url-encoded string
        final byte[] clientSessionChallenge = Base64.getUrlDecoder().decode(assertionResponse.getCollectedClientData().getChallenge());
        if (!Arrays.equals(sessionChallenge, clientSessionChallenge)) {
            throw new ResponseException("Returned challenge incorrect");
        }
        Log.info("Successfully verified session and challenge data");
    }

    public CredentialStore validateAndFindCredential(
            final PublicKeyCredential cred,
            final Long userId,
            final String sessionId) throws ResponseException {

        if (!(cred.getResponse() instanceof AuthenticatorAssertionResponse)) {
            throw new ResponseException("Invalid authenticator response");
        }

        final AuthenticatorAssertionResponse assertionResponse =
                (AuthenticatorAssertionResponse) cred.getResponse();

        final Set<CredentialStore> savedCreds = credentialStoreService.findByUserId(userId);
        if (savedCreds == null || savedCreds.size() == 0) {
            throw new ResponseException("No credentials registered for this user");
        }

        try {
            verifySessionAndChallenge(assertionResponse, userId, sessionId);
        } catch (ResponseException e1) {
            throw new ResponseException("Unable to verify session and challenge data");
        }

        CredentialStore credential = null;
        for (final CredentialStore saved : savedCreds) {
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
            final PublicKeyCredential cred,
            final Long userId,
            final String sessionId,
            final CredentialStore savedCredential) throws ServletException {

        final AuthenticatorAssertionResponse assertionResponse =
                (AuthenticatorAssertionResponse) cred.getResponse();

        Log.info("-- Verifying signature --");
        final AuthenticatorAttestationResponse storedAttData;
        try {
            storedAttData = new AuthenticatorAttestationResponse(savedCredential.getAttestationObjectBytes());
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

        credentialStoreService.updateSignCount(savedCredential, assertionResponse.getAuthenticatorData().getSignCount());

        Log.info("Signature verified");
    }

}
