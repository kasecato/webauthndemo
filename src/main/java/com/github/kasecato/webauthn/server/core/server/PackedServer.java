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
import com.github.kasecato.webauthn.server.core.objects.EccKey;
import com.github.kasecato.webauthn.server.core.objects.PackedAttestationStatement;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredential;
import com.github.kasecato.webauthn.server.core.objects.RsaKey;
import com.google.common.primitives.Bytes;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.logging.Logger;

public class PackedServer extends Server {

    private static final Logger Log = Logger.getLogger(PackedServer.class.getName());

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
            throw new WebAuthnException("Unable to verify session and challenge data", e1);
        }

        final byte[] clientDataHash = Crypto.sha256Digest(attResponse.getClientDataBytes());

        final byte[] rpIdHash = Crypto.sha256Digest(rpId.getBytes());

        if (!Arrays.equals(attResponse.getAttestationObject().getAuthData().getRpIdHash(),
                rpIdHash)) {
            throw new WebAuthnException("RPID hash incorrect");
        }

        if (!(attResponse.getAttestationObject().getAuthData().getAttData()
                .getPublicKey() instanceof EccKey) && !(attResponse.getAttestationObject().getAuthData().getAttData()
                .getPublicKey() instanceof RsaKey)) {
            throw new WebAuthnException("Supported key not provided");
        }

        final PackedAttestationStatement attStmt =
                (PackedAttestationStatement) attResponse.getAttestationObject().getAttStmt();

        try {
            /*
             * Signatures are signed over the concatenation of Authenticator data and Client Data Hash
             */
            final byte[] signedBytes =
                    Bytes.concat(attResponse.getAttestationObject().getAuthData().encode(), clientDataHash);

            final StringBuilder buf = new StringBuilder();
            for (final byte b : signedBytes) {
                buf.append(String.format("%02X ", b));
            }

            Log.info("Signed bytes: " + buf.toString());

            // TODO Make attStmt.attestnCert an X509Certificate right off the
            // bat.
            final DataInputStream inputStream =
                    new DataInputStream(new ByteArrayInputStream(attStmt.getAttestnCert()));
            final X509Certificate attestationCertificate = (X509Certificate) CertificateFactory
                    .getInstance("X.509").generateCertificate(inputStream);

            String signatureAlgorithm;
            try {
                signatureAlgorithm = AlgorithmIdentifierMapper.get(
                        attResponse.getAttestationObject().getAuthData().getAttData().getPublicKey().getAlg())
                        .getJavaAlgorithm();
            } catch (Exception e) {
                // Default to ES256
                signatureAlgorithm = "SHA256withECDSA";
            }

            if (!Crypto.verifySignature(attestationCertificate, signedBytes, attStmt.getSig(),
                    signatureAlgorithm)) {
                throw new SignatureException("Signature invalid");
            }
        } catch (final CertificateException e) {
            throw new WebAuthnException("Error when parsing attestationCertificate");
        } catch (final WebAuthnException e) {
            throw new WebAuthnException("Failure while verifying signature", e);
        } catch (final CborException e) {
            throw new WebAuthnException("Unable to reencode authenticator data");
        }

        // TODO Check trust anchors
        // TODO Check if self-attestation(/is allowed)
        // TODO Check X.509 certs

    }

    @Deprecated
    @Override
    public int verifyAssertion(
            final PublicKeyCredential cred,
            final CredentialModel savedCred)
            throws WebAuthnException {

        final AuthenticatorAssertionResponse assertionResponse =
                (AuthenticatorAssertionResponse) cred.getResponse();

        Log.info("-- Verifying signature --");
        final AuthenticatorAttestationResponse storedAttData;
        try {
            storedAttData = new AuthenticatorAttestationResponse(savedCred.getAttestationObjectBytes());
        } catch (final ResponseException | CborException e) {
            throw new WebAuthnException("Stored attestation missing");
        }

        if (!(storedAttData.getAttestationObject().getAuthData().getAttData()
                .getPublicKey() instanceof EccKey)) {
            throw new WebAuthnException("U2f-capable key not provided");
        }


        // if (assertionResponse.getAuthenticatorData().getSignCount() <=
        // savedCredential.getSignCount()) {
        // throw new ServletException("Sign count invalid");
        // }

        Log.info("Signature verified");

        return assertionResponse.getAuthenticatorData().getSignCount();
    }

}
