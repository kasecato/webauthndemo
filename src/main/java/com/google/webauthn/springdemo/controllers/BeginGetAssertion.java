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

package com.google.webauthn.springdemo.controllers;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.webauthn.springdemo.entities.SessionDataN;
import com.google.webauthn.springdemo.entities.UserN;
import com.google.webauthn.springdemo.objects.AuthenticationExtensionsN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialDescriptorN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialRequestOptionsN;
import com.google.webauthn.springdemo.objects.UserVerificationRequirement;
import com.google.webauthn.springdemo.services.SessionDataNService;
import com.google.webauthn.springdemo.services.UserNService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class BeginGetAssertion {

    private final SessionDataNService sessionDataNService;
    private final UserNService userNService;

    @Autowired
    public BeginGetAssertion(
            final SessionDataNService sessionDataNService,
            final UserNService userNService) {

        this.sessionDataNService = sessionDataNService;
        this.userNService = userNService;
    }

    @RequestMapping(
            path = "/BeginGetAssertion",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected BeginGetAssertionModel postBeginGetAssertion(
            @RequestHeader("Host") final String host,
            final Authentication authentication) {

        final String username = authentication.getName();
        final UserN user = userNService.find(username).orElseThrow(RuntimeException::new);
        final String rpId = host.split(":")[0];
        // String rpId = (request.isSecure() ? "https://" : "http://") + request.getHeader("Host");
        final PublicKeyCredentialRequestOptionsN assertion = new PublicKeyCredentialRequestOptionsN(rpId);
        final SessionDataN session = new SessionDataN(user.getId(), assertion.getChallenge(), rpId);
        sessionDataNService.save(session);
        assertion.populateAllowList(user.getCredentials());

        return new BeginGetAssertionModel(session, assertion);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static class BeginGetAssertionModel {

        private final SessionDataN session;

        private final byte[] challenge;

        private final Long timeout;
        private final String rpId;
        private final List<PublicKeyCredentialDescriptorN> allowCredentials;
        private final UserVerificationRequirement userVerification;
        private final AuthenticationExtensionsN extensions;

        public BeginGetAssertionModel(
                final SessionDataN session,
                final PublicKeyCredentialRequestOptionsN options) {

            this.session = session;
            this.challenge = options.getChallenge();
            this.timeout = options.getTimeout();
            this.rpId = options.getRpId();
            this.allowCredentials = options.getAllowCredentials();
            this.userVerification = options.getUserVerification();
            this.extensions = options.getExtensions();
        }

        public SessionDataN getSession() {
            return session;
        }

        public byte[] getChallenge() {
            return challenge;
        }

        public Long getTimeout() {
            return timeout;
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

        public AuthenticationExtensionsN getExtensions() {
            return extensions;
        }

    }

}
