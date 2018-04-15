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
import com.github.kasecato.webauthn.server.core.controllers.CredentialsCreate;
import com.github.kasecato.webauthn.server.core.objects.AttestationConveyancePreference;
import com.github.kasecato.webauthn.server.core.objects.AuthenticationExtensions;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorSelectionCriteria;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialCreationOptions;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialDescriptor;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialEntity;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialParameters;
import com.github.kasecato.webauthn.server.core.objects.PublicKeyCredentialUserEntity;
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

import java.util.ArrayList;

@RestController
public class BeginMakeCredential {

    private final SessionDataService sessionDataService;
    private final UserService userService;

    @Autowired
    public BeginMakeCredential(
            final SessionDataService sessionDataService,
            final UserService userService) {

        this.sessionDataService = sessionDataService;
        this.userService = userService;
    }

    @RequestMapping(
            path = "/BeginMakeCredential",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected BeginMakeCredentialModel postBeginMakeCredential(
            @RequestHeader("Host") final String host,
            final Authentication authentication) {

        final String username = authentication.getName();
        final User user = userService.find(username).orElseThrow(RuntimeException::new);
        final String email = user.getEmail();
        // String rpId = (request.isSecure() ? "https://" : "http://") + request.getHeader("Host");
        final String rpId = host.split(":")[0];
        final String rpName = email;

        final PublicKeyCredentialCreationOptions options = CredentialsCreate.getCreationOptions(rpId, rpName, email, email);

        final SessionData session = new SessionData(user.getId(), options.getChallenge(), rpId);
        final SessionData sessionSaved = sessionDataService.save(session);

        return new BeginMakeCredentialModel(sessionSaved, options);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static class BeginMakeCredentialModel {

        private final SessionData session;

        private final PublicKeyCredentialEntity rp;
        private final PublicKeyCredentialUserEntity user;
        private final byte[] challenge;
        private final ArrayList<PublicKeyCredentialParameters> pubKeyCredParams;

        private final Long timeout;
        private final ArrayList<PublicKeyCredentialDescriptor> excludeCredentials;
        private final AuthenticatorSelectionCriteria authenticatorSelection;
        private final AttestationConveyancePreference attestation;
        private final AuthenticationExtensions extensions;

        public BeginMakeCredentialModel(
                final SessionData session,
                final PublicKeyCredentialCreationOptions options) {

            this.session = session;

            this.rp = options.getRp();
            this.user = options.getUser();
            this.challenge = options.getChallenge();
            this.pubKeyCredParams = options.getPubKeyCredParams();

            this.timeout = options.getTimeout();
            this.excludeCredentials = options.getExcludeCredentials();
            this.authenticatorSelection = options.getAuthenticatorSelection();
            this.attestation = options.getAttestation();
            this.extensions = options.getExtensions();
        }

        public SessionData getSession() {
            return session;
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

}
