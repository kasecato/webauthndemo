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
import com.google.webauthn.springdemo.entities.CredentialStore;
import com.google.webauthn.springdemo.exceptions.ResponseException;
import com.google.webauthn.springdemo.exceptions.WebAuthnException;
import com.google.webauthn.springdemo.objects.AuthenticatorAssertionResponse;
import com.google.webauthn.springdemo.objects.AuthenticatorAttestationResponse;
import com.google.webauthn.springdemo.objects.EccKey;
import com.google.webauthn.springdemo.objects.FidoU2fAttestationStatement;
import com.google.webauthn.springdemo.objects.PublicKeyCredential;
import com.google.webauthn.springdemo.services.CredentialStoreService;
import com.google.webauthn.springdemo.services.SessionDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.ServletException;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.logging.Logger;

@Service
public class U2fServer extends Server {

    private static final Logger Log = Logger.getLogger(U2fServer.class.getName());

    @Autowired
    public U2fServer(
            final CredentialStoreService credentialStoreService,
            final SessionDataService sessionDataService) {

        super(credentialStoreService, sessionDataService);
    }

    @Deprecated
    @Override
    @Transactional(rollbackFor = Exception.class)
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
        } catch (final ResponseException | CborException e) {
            throw new ServletException("Stored attestation missing");
        }

        if (!(storedAttData.getAttestationObject().getAuthData().getAttData()
                .getPublicKey() instanceof EccKey)) {
            throw new ServletException("U2f-capable key not provided");
        }

        final EccKey publicKey =
                (EccKey) storedAttData.getAttestationObject().getAuthData().getAttData().getPublicKey();
        try {
            /*
             * U2F authentication signatures are signed over the concatenation of
             *
             * 32 byte application parameter hash
             *
             * 1 byte user presence
             *
             * 4 byte big-endian representation of the counter
             *
             * 32 byte challenge parameter (ie SHA256 hash of clientData)
             */
            byte[] clientDataHash = Crypto.sha256Digest(assertionResponse.getClientDataBytes());

            byte[] signedBytes =
                    Bytes.concat(storedAttData.getAttestationObject().getAuthData().getRpIdHash(),
                            new byte[]{
                                    (assertionResponse.getAuthenticatorData().isUP() == true ? (byte) 1 : (byte) 0)},
                            ByteBuffer.allocate(4).putInt(assertionResponse.getAuthenticatorData().getSignCount())
                                    .array(),
                            clientDataHash);
            if (!Crypto.verifySignature(Crypto.decodePublicKey(publicKey.getX(), publicKey.getY()),
                    signedBytes, assertionResponse.getSignatureBytes())) {
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

    @Transactional(rollbackFor = Exception.class)
    public void registerCredential(
            final PublicKeyCredential cred,
            final Long userId,
            final String session,
            final String originString,
            final String rpId) throws ServletException {

        if (!(cred.getResponse() instanceof AuthenticatorAttestationResponse)) {
            throw new ServletException("Invalid response structure");
        }

        final AuthenticatorAttestationResponse attResponse =
                (AuthenticatorAttestationResponse) cred.getResponse();

        final Set<CredentialStore> savedCreds = credentialStoreService.findByUserId(userId);
        for (final CredentialStore c : savedCreds) {
            if (c.getPublicKeyCredentialId().equals(cred.getId())) {
                throw new ServletException("Credential already registered for this user");
            }
        }

        try {
            verifySessionAndChallenge(attResponse, userId, session);
        } catch (ResponseException e1) {
            throw new ServletException("Unable to verify session and challenge data", e1);
        }

        final byte[] clientDataHash = Crypto.sha256Digest(attResponse.getClientDataBytes());

        final byte[] rpIdHash = Crypto.sha256Digest(rpId.getBytes());

        if (!Arrays.equals(attResponse.getAttestationObject().getAuthData().getRpIdHash(),
                rpIdHash)) {
            throw new ServletException("RPID hash incorrect");
        }

        if (!(attResponse.getAttestationObject().getAuthData().getAttData()
                .getPublicKey() instanceof EccKey)) {
            throw new ServletException("U2f-capable key not provided");
        }

        final FidoU2fAttestationStatement attStmt =
                (FidoU2fAttestationStatement) attResponse.getAttestationObject().getAttStmt();

        final EccKey publicKey =
                (EccKey) attResponse.getAttestationObject().getAuthData().getAttData().getPublicKey();

        try {
            /*
             * U2F registration signatures are signed over the concatenation of
             *
             * 1 byte RFU (0)
             *
             * 32 byte application parameter hash
             *
             * 32 byte challenge parameter
             *
             * key handle
             *
             * 65 byte user public key represented as {0x4, X, Y}
             */
            final byte[] signedBytes = Bytes.concat(new byte[]{0}, rpIdHash, clientDataHash, cred.getRawId(),
                    new byte[]{0x04}, publicKey.getX(), publicKey.getY());

            // TODO Make attStmt.attestnCert an X509Certificate right off the
            // bat.
            final DataInputStream inputStream =
                    new DataInputStream(new ByteArrayInputStream(attStmt.getAttestnCert()));
            final X509Certificate attestationCertificate = (X509Certificate) CertificateFactory
                    .getInstance("X.509").generateCertificate(inputStream);

            if (!Crypto.verifySignature(attestationCertificate, signedBytes, attStmt.getSig())) {
                throw new ServletException("Signature invalid");
            }
        } catch (CertificateException e) {
            throw new ServletException("Error when parsing attestationCertificate");
        } catch (WebAuthnException e) {
            throw new ServletException("Failure while verifying signature", e);
        }

        // TODO Check trust anchors
        // TODO Check if self-attestation(/is allowed)
        // TODO Check X.509 certs

    }

}
