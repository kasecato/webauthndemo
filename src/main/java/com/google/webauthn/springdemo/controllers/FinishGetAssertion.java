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

import com.github.kasecato.webauthn.server.core.controllers.CredentialsGet;
import com.github.kasecato.webauthn.server.core.exceptions.ResponseException;
import com.github.kasecato.webauthn.server.core.exceptions.SignatureException;
import com.github.kasecato.webauthn.server.core.exceptions.WebAuthnException;
import com.github.kasecato.webauthn.server.core.models.CredentialModel;
import com.google.webauthn.springdemo.entities.SessionData;
import com.google.webauthn.springdemo.entities.User;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialResponse;
import com.google.webauthn.springdemo.services.CredentialStoreService;
import com.google.webauthn.springdemo.services.SessionDataService;
import com.google.webauthn.springdemo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.bind.DatatypeConverter;

@RestController
public class FinishGetAssertion {

    private final CredentialStoreService credentialStoreService;
    private final SessionDataService sessionDataService;
    private final UserService userService;

    @Autowired
    public FinishGetAssertion(
            final CredentialStoreService credentialStoreService,
            final SessionDataService sessionDataService,
            final UserService userService) {

        this.credentialStoreService = credentialStoreService;
        this.sessionDataService = sessionDataService;
        this.userService = userService;
    }

    @RequestMapping(
            path = "/FinishGetAssertion",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected PublicKeyCredentialResponse postFinishGetAssertion(
            @RequestParam("data") final String data,
            @RequestParam("session") final String session,
            final Authentication authentication) {

        final String username = authentication.getName();
        final User user = userService.find(username).orElseThrow(RuntimeException::new);

        final SessionData sessionData;
        try {
            sessionData = sessionDataService.findAndRemoveSession(user.getId(), session);
        } catch (final ResponseException e) {
            return new PublicKeyCredentialResponse(false, e.getMessage(), null);
        }

        final CredentialModel verifiedCred;
        try {
            verifiedCred = CredentialsGet.assertion(data, sessionData.getChallenge(), user.getCredentials());
            credentialStoreService.updateSignCount(verifiedCred.getId(), verifiedCred.getSignCount());
        } catch (final WebAuthnException | SignatureException | ResponseException e) {
            return new PublicKeyCredentialResponse(false, e.getMessage(), null);
        }

        final String handle = DatatypeConverter.printHexBinary(verifiedCred.getRawId());
        final PublicKeyCredentialResponse rsp = new PublicKeyCredentialResponse(true, "Successful assertion", handle);
        return rsp;
    }

}
