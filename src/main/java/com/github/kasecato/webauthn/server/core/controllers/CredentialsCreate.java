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
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorAttestationResponse;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredential;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialCreationOptions;
import com.github.kasecato.webauthn.server.core.server.AndroidSafetyNetServer;
import com.github.kasecato.webauthn.server.core.server.PackedServer;
import com.github.kasecato.webauthn.server.core.server.U2FServer;

import java.io.IOException;
import java.util.Base64;
import java.util.Collection;

public class CredentialsCreate {

    public static PublicKeyCredentialCreationOptions getCreationOptions(
            final String rpName,
            final String rpIcon,
            final String rpId,
            final String userName,
            final String userIcon,
            final String displayName,
            final String userId) {

        return new PublicKeyCredentialCreationOptions(rpName, rpIcon, rpId, userName, userIcon, displayName, userId);
    }

    public static CredentialModel create(
            final String rpId,
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
        final JsonNode authenticatorAttestationResponseJson = json.get("response");

        final AuthenticatorAttestationResponse attestation;
        try {
            attestation = new AuthenticatorAttestationResponse(authenticatorAttestationResponseJson);
        } catch (final ResponseException e) {
            throw new WebAuthnException(e.toString());
        }

        // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support padding.
        final byte[] credentialIdRaw = Base64.getUrlDecoder().decode(credentialId);
        final String credentialIdRecoded = Base64.getUrlEncoder().encodeToString(credentialIdRaw);

        final PublicKeyCredential cred = new PublicKeyCredential(credentialIdRecoded, type, credentialIdRaw, attestation);

        switch (cred.getAttestationType()) {
            case FIDOU2F:
                U2FServer.registerCredential(cred, savedChallengeBase64Encoded, savedCredentials, rpId);
                break;
            case ANDROIDSAFETYNET:
                AndroidSafetyNetServer.registerCredential(cred, savedChallengeBase64Encoded, savedCredentials, rpId);
                break;
            case PACKED:
                PackedServer.registerCredential(cred, savedChallengeBase64Encoded, savedCredentials, rpId);
                break;
            case NONE:
                break;
        }

        return new CredentialModel(credentialIdRecoded, credentialIdRaw, 0, attestation.getAttestationObjectBytes());
    }

}
