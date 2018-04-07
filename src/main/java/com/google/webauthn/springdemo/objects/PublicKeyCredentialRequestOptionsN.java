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
import com.google.webauthn.springdemo.entities.CredentialStoreN;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class PublicKeyCredentialRequestOptionsN {

    @JsonIgnore
    private static final int CHALLENGE_LENGTH = 32;

    @JsonIgnore
    private final SecureRandom random = new SecureRandom();

    // Required parameters
    private final byte[] challenge;
    private final String rpId;
    // Optional parameters
    private Long timeout;
    private List<PublicKeyCredentialDescriptorN> allowCredentials;
    private UserVerificationRequirement userVerification;
    private AuthenticationExtensionsN extensions;

    public PublicKeyCredentialRequestOptionsN(final String rpId) {
        challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        allowCredentials = new ArrayList<>();
        this.rpId = rpId;
    }

    public void populateAllowList(final Set<CredentialStoreN> credentials) {
        allowCredentials = credentials.stream()
                .map(storedCred -> new PublicKeyCredentialDescriptorN(PublicKeyCredentialType.PUBLIC_KEY, storedCred.getRawId(), new ArrayList<>()))
                .collect(Collectors.toList());
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public Long getTimeout() {
        return timeout;
    }

    public PublicKeyCredentialRequestOptionsN setTimeout(final Long timeout) {
        this.timeout = timeout;
        return this;
    }

    public String getRpId() {
        return rpId;
    }

    public List<PublicKeyCredentialDescriptorN> getAllowCredentials() {
        return allowCredentials;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public PublicKeyCredentialRequestOptionsN setUserVerification(final UserVerificationRequirement userVerification) {
        this.userVerification = userVerification;
        return this;
    }

    public AuthenticationExtensionsN getExtensions() {
        return extensions;
    }

    public PublicKeyCredentialRequestOptionsN setExtensions(final AuthenticationExtensionsN extensions) {
        this.extensions = extensions;
        return this;
    }

}
