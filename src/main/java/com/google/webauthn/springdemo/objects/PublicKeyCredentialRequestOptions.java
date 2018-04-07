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
import com.google.webauthn.springdemo.entities.CredentialStore;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class PublicKeyCredentialRequestOptions {

    @JsonIgnore
    private static final int CHALLENGE_LENGTH = 32;

    @JsonIgnore
    private final SecureRandom random = new SecureRandom();

    private final byte[] challenge;
    private Long timeout;
    private final String rpId;
    private List<PublicKeyCredentialDescriptor> allowCredentials;
    private UserVerificationRequirement userVerification;
    private AuthenticationExtensions extensions;

    public PublicKeyCredentialRequestOptions(final String rpId) {
        challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        allowCredentials = new ArrayList<>();
        this.rpId = rpId;
    }

    public void populateAllowList(final Set<CredentialStore> credentials) {
        allowCredentials = credentials.stream()
                .map(storedCred -> new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, storedCred.getRawId(), new ArrayList<>()))
                .collect(Collectors.toList());
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public Long getTimeout() {
        return timeout;
    }

    public PublicKeyCredentialRequestOptions setTimeout(final Long timeout) {
        this.timeout = timeout;
        return this;
    }

    public String getRpId() {
        return rpId;
    }

    public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
        return allowCredentials;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public PublicKeyCredentialRequestOptions setUserVerification(final UserVerificationRequirement userVerification) {
        this.userVerification = userVerification;
        return this;
    }

    public AuthenticationExtensions getExtensions() {
        return extensions;
    }

    public PublicKeyCredentialRequestOptions setExtensions(final AuthenticationExtensions extensions) {
        this.extensions = extensions;
        return this;
    }

}
