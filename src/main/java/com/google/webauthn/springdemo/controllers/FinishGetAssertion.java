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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.webauthn.springdemo.entities.CredentialStoreN;
import com.google.webauthn.springdemo.entities.UserN;
import com.google.webauthn.springdemo.exceptions.ResponseException;
import com.google.webauthn.springdemo.objects.AuthenticatorAssertionResponseN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialResponseN;
import com.google.webauthn.springdemo.server.ServerN;
import com.google.webauthn.springdemo.services.UserNService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.Base64;

@RestController
public class FinishGetAssertion {

    private final UserNService userNService;
    private final ServerN serverN;

    @Autowired
    public FinishGetAssertion(
            final UserNService userNService,
            final ServerN serverN) {

        this.userNService = userNService;
        this.serverN = serverN;
    }

    @RequestMapping(
            path = "/FinishGetAssertion",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected PublicKeyCredentialResponseN postFinishGetAssertion(
            @RequestParam("data") final String data,
            @RequestParam("session") final String session,
            final Authentication authentication)
            throws ServletException {

        final String username = authentication.getName();
        final UserN user = userNService.find(username).orElseThrow(RuntimeException::new);

        final JsonNode json;
        try {
            json = new ObjectMapper().readTree(data);
        } catch (final IOException e) {
            throw new ServletException("Input not valid json");
        }

        final String credentialId = json.get("id").textValue();
        final String type = json.get("type").textValue();
        final JsonNode assertionJson = json.get("response");
        if (assertionJson.isNull()) {
            throw new ServletException("Missing element 'response'");
        }

        final AuthenticatorAssertionResponseN assertion;
        try {
            assertion = new AuthenticatorAssertionResponseN(assertionJson);
        } catch (final ResponseException e) {
            throw new ServletException(e.toString());
        }

        // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support
        // padding.
        final String credentialIdRecoded = Base64.getUrlEncoder().encodeToString(Base64.getUrlDecoder().decode(credentialId));
        final PublicKeyCredentialN cred = new PublicKeyCredentialN(assertion, credentialIdRecoded, type, Base64.getUrlDecoder().decode(credentialId));

        final CredentialStoreN savedCredential;
        try {
            savedCredential = serverN.validateAndFindCredential(cred, user.getId(), session);
        } catch (ResponseException e) {
            throw new ServletException("Unable to validate assertion", e);
        }


        // switch (savedCredential.getCredential().getAttestationType()) {
        // case FIDOU2F:
        // U2fServer.verifyAssertion(cred, currentUser, session, savedCredential);
        // break;
        // case ANDROIDSAFETYNET:
        // AndroidSafetyNetServer.verifyAssertion(cred, currentUser, session, savedCredential);
        // break;
        // case PACKED:
        // PackedServer.verifyAssertion(cred, currentUser, session, savedCredential);
        // break;
        // }

        serverN.verifyAssertion(cred, user.getId(), session, savedCredential);

        final String handle = DatatypeConverter.printHexBinary(savedCredential.getRawId());
        final PublicKeyCredentialResponseN rsp = new PublicKeyCredentialResponseN(true, "Successful assertion", handle);

        return rsp;
    }

}
