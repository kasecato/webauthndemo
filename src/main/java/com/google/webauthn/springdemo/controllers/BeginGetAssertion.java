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
import com.github.kasecato.webauthn.server.core.controllers.CredentialsGet;
import com.github.kasecato.webauthn.server.core.objects.AuthenticationExtensions;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialDescriptor;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialRequestOptions;
import com.github.kasecato.webauthn.server.core.objects.UserVerificationRequirement;
import com.google.webauthn.springdemo.entities.SessionData;
import com.google.webauthn.springdemo.entities.User;
import com.google.webauthn.springdemo.services.SessionDataService;
import com.google.webauthn.springdemo.services.UserService;
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

    private final SessionDataService sessionDataService;
    private final UserService userService;

    @Autowired
    public BeginGetAssertion(
            final SessionDataService sessionDataService,
            final UserService userService) {

        this.sessionDataService = sessionDataService;
        this.userService = userService;
    }

    @RequestMapping(
            path = "/BeginGetAssertion",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected BeginGetAssertionModel postBeginGetAssertion(
            @RequestHeader("Host") final String host,
            final Authentication authentication) {

        final String username = authentication.getName();
        final User user = userService.find(username).orElseThrow(RuntimeException::new);
        final String rpId = host.split(":")[0];
        // String rpId = (request.isSecure() ? "https://" : "http://") + request.getHeader("Host");

        final PublicKeyCredentialRequestOptions assertion = CredentialsGet.getReuqestOptions();
        assertion.setRpId(rpId);
        assertion.populateAllowList(user.getCredentials());

        final SessionData session = new SessionData(user.getId(), assertion.getChallenge(), rpId);
        sessionDataService.save(session);

        return new BeginGetAssertionModel(session, assertion);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static class BeginGetAssertionModel {

        private final SessionData session;

        private final byte[] challenge;

        private final Long timeout;
        private final String rpId;
        private final List<PublicKeyCredentialDescriptor> allowCredentials;
        private final UserVerificationRequirement userVerification;
        private final AuthenticationExtensions extensions;

        public BeginGetAssertionModel(
                final SessionData session,
                final PublicKeyCredentialRequestOptions options) {

            this.session = session;
            this.challenge = options.getChallenge();
            this.timeout = options.getTimeout();
            this.rpId = options.getRpId();
            this.allowCredentials = options.getAllowCredentials();
            this.userVerification = options.getUserVerification();
            this.extensions = options.getExtensions();
        }

        public SessionData getSession() {
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

        public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
            return allowCredentials;
        }

        public UserVerificationRequirement getUserVerification() {
            return userVerification;
        }

        public AuthenticationExtensions getExtensions() {
            return extensions;
        }

    }

}
