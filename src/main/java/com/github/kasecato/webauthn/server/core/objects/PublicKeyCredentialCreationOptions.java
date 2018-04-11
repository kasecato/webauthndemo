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

package com.github.kasecato.webauthn.server.core.objects;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import java.security.SecureRandom;
import java.util.ArrayList;

@JsonInclude(Include.NON_NULL)
public class PublicKeyCredentialCreationOptions {

    @JsonIgnore
    private final int CHALLENGE_LENGTH = 32;
    @JsonIgnore
    private final SecureRandom random = new SecureRandom();

    private final PublicKeyCredentialEntity rp;
    private final PublicKeyCredentialUserEntity user;

    private final byte[] challenge;
    private ArrayList<PublicKeyCredentialParameters> pubKeyCredParams;

    private Long timeout;
    private ArrayList<PublicKeyCredentialDescriptor> excludeCredentials;
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;
    private AuthenticationExtensions extensions;

    public PublicKeyCredentialCreationOptions(
            final String rpName,
            final String rpIcon,
            final String rpId,
            final String userName,
            final String userIcon,
            final String displayName,
            final String userId) {

        rp = new PublicKeyCredentialRpEntity(rpId, rpName, rpIcon);
        user = new PublicKeyCredentialUserEntity(userName, userIcon, displayName, userId.getBytes());

        challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);

        pubKeyCredParams = new ArrayList<>();
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.ES256));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.ES384));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.ES512));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.RS256));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.RS384));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.RS512));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.PS256));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.PS384));
        pubKeyCredParams.add(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, Algorithm.PS512));
    }

    public PublicKeyCredentialEntity getRp() {
        return rp;
    }

    public PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public ArrayList<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public PublicKeyCredentialCreationOptions setPubKeyCredParams(final ArrayList<PublicKeyCredentialParameters> pubKeyCredParams) {
        this.pubKeyCredParams = pubKeyCredParams;
        return this;
    }

    public Long getTimeout() {
        return timeout;
    }

    public PublicKeyCredentialCreationOptions setTimeout(final Long timeout) {
        this.timeout = timeout;
        return this;
    }

    public ArrayList<PublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    public PublicKeyCredentialCreationOptions setExcludeCredentials(final ArrayList<PublicKeyCredentialDescriptor> excludeCredentials) {
        this.excludeCredentials = excludeCredentials;
        return this;
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public PublicKeyCredentialCreationOptions setAuthenticatorSelection(final AuthenticatorSelectionCriteria authenticatorSelection) {
        this.authenticatorSelection = authenticatorSelection;
        return this;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public PublicKeyCredentialCreationOptions setAttestation(final AttestationConveyancePreference attestation) {
        this.attestation = attestation;
        return this;
    }

    public AuthenticationExtensions getExtensions() {
        return extensions;
    }

    public PublicKeyCredentialCreationOptions setExtensions(final AuthenticationExtensions extensions) {
        this.extensions = extensions;
        return this;
    }

}
