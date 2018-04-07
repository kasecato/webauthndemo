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
import com.google.webauthn.springdemo.objects.AttestationConveyancePreference;
import com.google.webauthn.springdemo.objects.AuthenticationExtensionsN;
import com.google.webauthn.springdemo.objects.AuthenticatorSelectionCriteriaN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialCreationOptionsN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialDescriptorN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialEntityN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialParametersN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialUserEntityN;
import com.google.webauthn.springdemo.services.SessionDataNService;
import com.google.webauthn.springdemo.services.UserNService;
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

    private final SessionDataNService sessionDataNService;
    private final UserNService userNService;

    @Autowired
    public BeginMakeCredential(
            final SessionDataNService sessionDataNService,
            final UserNService userNService) {

        this.sessionDataNService = sessionDataNService;
        this.userNService = userNService;
    }

    @RequestMapping(
            path = "/BeginMakeCredential",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected BeginMakeCredentialModel postBeginMakeCredential(
            @RequestHeader("Host") final String host,
            final Authentication authentication) {

        final String username = authentication.getName();
        final UserN user = userNService.find(username).orElseThrow(RuntimeException::new);
        final String email = user.getEmail();
        // String rpId = (request.isSecure() ? "https://" : "http://") + request.getHeader("Host");
        final String rpId = host.split(":")[0];
        final String rpName = email;

        final PublicKeyCredentialCreationOptionsN options = new PublicKeyCredentialCreationOptionsN(email, email, rpId, rpName);

        final SessionDataN session = new SessionDataN(user.getId(), options.getChallenge(), rpId);
        final SessionDataN sessionSaved = sessionDataNService.save(session);

        return new BeginMakeCredentialModel(sessionSaved, options);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static class BeginMakeCredentialModel {

        private final SessionDataN session;

        private final PublicKeyCredentialEntityN rp;
        private final PublicKeyCredentialUserEntityN user;
        private final byte[] challenge;
        private final ArrayList<PublicKeyCredentialParametersN> pubKeyCredParams;

        private final Long timeout;
        private final ArrayList<PublicKeyCredentialDescriptorN> excludeCredentials;
        private final AuthenticatorSelectionCriteriaN authenticatorSelection;
        private final AttestationConveyancePreference attestation;
        private final AuthenticationExtensionsN extensions;

        public BeginMakeCredentialModel(
                final SessionDataN session,
                final PublicKeyCredentialCreationOptionsN options) {

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

        public SessionDataN getSession() {
            return session;
        }

        public PublicKeyCredentialEntityN getRp() {
            return rp;
        }

        public PublicKeyCredentialUserEntityN getUser() {
            return user;
        }

        public byte[] getChallenge() {
            return challenge;
        }

        public ArrayList<PublicKeyCredentialParametersN> getPubKeyCredParams() {
            return pubKeyCredParams;
        }

        public Long getTimeout() {
            return timeout;
        }

        public ArrayList<PublicKeyCredentialDescriptorN> getExcludeCredentials() {
            return excludeCredentials;
        }

        public AuthenticatorSelectionCriteriaN getAuthenticatorSelection() {
            return authenticatorSelection;
        }

        public AttestationConveyancePreference getAttestation() {
            return attestation;
        }

        public AuthenticationExtensionsN getExtensions() {
            return extensions;
        }

    }

}
