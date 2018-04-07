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
import com.google.webauthn.springdemo.entities.CredentialStore;
import com.google.webauthn.springdemo.entities.User;
import com.google.webauthn.springdemo.exceptions.ResponseException;
import com.google.webauthn.springdemo.objects.AuthenticatorAttestationResponse;
import com.google.webauthn.springdemo.objects.PublicKeyCredential;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialResponse;
import com.google.webauthn.springdemo.server.AndroidSafetyNetServer;
import com.google.webauthn.springdemo.server.PackedServer;
import com.google.webauthn.springdemo.server.U2fServer;
import com.google.webauthn.springdemo.services.CredentialStoreService;
import com.google.webauthn.springdemo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

@RestController
public class FinishMakeCredential {

    private final AndroidSafetyNetServer androidSafetyNetServer;
    private final CredentialStoreService credentialStoreService;
    private final ObjectMapper jacksonMapper;
    private final PackedServer packedServer;
    private final U2fServer u2FServer;
    private final UserService userService;

    @Autowired
    public FinishMakeCredential(
            final AndroidSafetyNetServer androidSafetyNetServer,
            final CredentialStoreService credentialStoreService,
            final ObjectMapper jacksonMapper,
            final PackedServer packedServer,
            final U2fServer u2FServer,
            final UserService userService) {

        this.androidSafetyNetServer = androidSafetyNetServer;
        this.credentialStoreService = credentialStoreService;
        this.jacksonMapper = jacksonMapper;
        this.packedServer = packedServer;
        this.u2FServer = u2FServer;
        this.userService = userService;
    }

    @RequestMapping(
            path = "/FinishMakeCredential",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected PublicKeyCredentialResponse postFinishMakeCredential(
            @RequestHeader("Host") final String host,
            @RequestParam("data") final String data,
            @RequestParam("session") final String session,
            final HttpServletRequest request,
            final Authentication authentication)
            throws ServletException {

        final String username = authentication.getName();
        final User user = userService.find(username).orElseThrow(RuntimeException::new);

        final JsonNode json;
        try {
            json = jacksonMapper.readTree(data);
        } catch (IOException e) {
            throw new ServletException("Input not valid json");
        }
        final String credentialId = json.get("id").textValue();
        final String type = json.get("type").textValue();
        final JsonNode makeCredentialResponse = json.get("response");

        final AuthenticatorAttestationResponse attestation;
        try {
            attestation = new AuthenticatorAttestationResponse(makeCredentialResponse);
        } catch (ResponseException e) {
            throw new ServletException(e.toString());
        }

        // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support
        // padding.
        final String credentialIdRecoded = Base64.getUrlEncoder().encodeToString(Base64.getUrlDecoder().decode(credentialId));

        final PublicKeyCredential cred = new PublicKeyCredential(attestation, credentialIdRecoded, type, Base64.getUrlDecoder().decode(credentialId));

        final String domain = (request.isSecure() ? "https://" : "http://") + host;
        final String rpId = host.split(":")[0];
        switch (cred.getAttestationType()) {
            case FIDOU2F:
                u2FServer.registerCredential(cred, user.getId(), session, domain, rpId);
                break;
            case ANDROIDSAFETYNET:
                androidSafetyNetServer.registerCredential(cred, user.getId(), session, rpId);
                break;
            case PACKED:
                packedServer.registerCredential(cred, user.getId(), session, rpId);
                break;
            case NONE:
                break;
        }

        final CredentialStore credential = new CredentialStore(user.getId(), cred);
        credentialStoreService.save(credential);

        final PublicKeyCredentialResponse rsp = new PublicKeyCredentialResponse(true, "Successfully created credential", null);

        return rsp;
    }

}
