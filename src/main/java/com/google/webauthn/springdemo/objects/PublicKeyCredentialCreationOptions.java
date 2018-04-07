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

package com.google.webauthn.springdemo.objects;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;

public class PublicKeyCredentialCreationOptions {

    @JsonIgnore
    private final int CHALLENGE_LENGTH = 32;

    @JsonIgnore
    private final SecureRandom random = new SecureRandom();

    private final PublicKeyCredentialEntity rp;
    private final PublicKeyCredentialUserEntity user;
    private final byte[] challenge;
    private final ArrayList<PublicKeyCredentialParameters> pubKeyCredParams;

    private final Long timeout;
    private final ArrayList<PublicKeyCredentialDescriptor> excludeCredentials;
    private final AuthenticatorSelectionCriteria authenticatorSelection;
    private final AttestationConveyancePreference attestation;
    private final AuthenticationExtensions extensions;

    public PublicKeyCredentialCreationOptions(
            final String userName,
            final String userId,
            final String rpId,
            final String rpName) {

        timeout = null;
        authenticatorSelection = null;
        attestation = null;
        pubKeyCredParams = new ArrayList<>();
        excludeCredentials = new ArrayList<>();
        rp = new PublicKeyCredentialRpEntity(rpId, rpName, null);
        user = new PublicKeyCredentialUserEntity(userName, userId.getBytes());

        challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);
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
        extensions = null;
    }

    public void excludeCredential(final PublicKeyCredentialDescriptor credential) {
        excludeCredentials.add(credential);
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

    public Long getTimeout() {
        return timeout;
    }

    public ArrayList<PublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    public void setExcludeCredentials(final Collection<PublicKeyCredentialDescriptor> excludeCredentials) {
        this.excludeCredentials.clear();
        this.excludeCredentials.addAll(excludeCredentials);
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public AuthenticationExtensions getExtensions() {
        return extensions;
    }

}
