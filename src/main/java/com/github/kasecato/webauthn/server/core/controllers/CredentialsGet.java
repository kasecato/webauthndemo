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

package com.github.kasecato.webauthn.server.core.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.kasecato.webauthn.server.core.exceptions.ResponseException;
import com.github.kasecato.webauthn.server.core.exceptions.SignatureException;
import com.github.kasecato.webauthn.server.core.exceptions.WebAuthnException;
import com.github.kasecato.webauthn.server.core.models.CredentialModel;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorAssertionResponse;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredential;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialRequestOptions;
import com.github.kasecato.webauthn.server.core.server.Server;

import java.io.IOException;
import java.util.Base64;
import java.util.Collection;

public class CredentialsGet {

    public static PublicKeyCredentialRequestOptions getReuqestOptions() {

        return new PublicKeyCredentialRequestOptions();
    }

    public static CredentialModel assertion(
            final String publicKeyCredentialJson,
            final String savedChallengeBase64Encoded,
            final Collection<CredentialModel> savedCredentials)
            throws WebAuthnException, SignatureException {

        final JsonNode json;
        try {
            json = new ObjectMapper().readTree(publicKeyCredentialJson);
        } catch (final IOException e) {
            throw new WebAuthnException("Input not valid json");
        }

        final String credentialId = json.get("id").textValue();
        final String type = json.get("type").textValue();
        final JsonNode assertionJson = json.get("response");
        if (assertionJson.isNull()) {
            throw new WebAuthnException("Missing element 'response'");
        }

        final AuthenticatorAssertionResponse assertion;
        try {
            assertion = new AuthenticatorAssertionResponse(assertionJson);
        } catch (final ResponseException e) {
            throw new WebAuthnException(e.toString());
        }

        // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support padding.
        final String credentialIdRecoded = Base64.getUrlEncoder().encodeToString(Base64.getUrlDecoder().decode(credentialId));
        final PublicKeyCredential cred = new PublicKeyCredential(credentialIdRecoded, type, Base64.getUrlDecoder().decode(credentialId), assertion);

        final CredentialModel savedCredential;
        try {
            savedCredential = Server.validateAndFindCredential(cred, savedChallengeBase64Encoded, savedCredentials);
        } catch (ResponseException e) {
            throw new WebAuthnException("Unable to validate assertion", e);
        }


        // switch (savedCredential.getCredential().getAttestationType()) {
        // case FIDOU2F:
        // U2fServer.verifyAssertion(cred, currentUser, session, savedCredential);
        // break;
        // case ANDROIDSAFETYNET:
        // AndroidSafetyNetServer.verifyAssertion(cred, currentUser, session, savedCredential);
        // break;
        // case PACKED:
        // PackedServer.verifyAssertion(cred, currentUser, session, savedCredential);
        // break;
        // }

        final int signCount = new Server().verifyAssertion(cred, savedCredential);
        savedCredential.setSignCount(signCount);

        return savedCredential;
    }

}
