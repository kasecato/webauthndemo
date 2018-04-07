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
import com.google.webauthn.springdemo.objects.AuthenticatorAttestationResponseN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialN;
import com.google.webauthn.springdemo.objects.PublicKeyCredentialResponseN;
import com.google.webauthn.springdemo.server.AndroidSafetyNetServerN;
import com.google.webauthn.springdemo.server.PackedServerN;
import com.google.webauthn.springdemo.server.U2fServerN;
import com.google.webauthn.springdemo.services.CredentialStoreNService;
import com.google.webauthn.springdemo.services.UserNService;
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

    private final AndroidSafetyNetServerN androidSafetyNetServerN;
    private final CredentialStoreNService credentialStoreNService;
    private final ObjectMapper jacksonMapper;
    private final PackedServerN packedServerN;
    private final U2fServerN u2fServerN;
    private final UserNService userNService;

    @Autowired
    public FinishMakeCredential(
            final AndroidSafetyNetServerN androidSafetyNetServerN,
            final CredentialStoreNService credentialStoreNService,
            final ObjectMapper jacksonMapper,
            final PackedServerN packedServerN,
            final U2fServerN u2fServerN,
            final UserNService userNService) {

        this.androidSafetyNetServerN = androidSafetyNetServerN;
        this.credentialStoreNService = credentialStoreNService;
        this.jacksonMapper = jacksonMapper;
        this.packedServerN = packedServerN;
        this.u2fServerN = u2fServerN;
        this.userNService = userNService;
    }

    @RequestMapping(
            path = "/FinishMakeCredential",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected PublicKeyCredentialResponseN postFinishMakeCredential(
            @RequestHeader("Host") final String host,
            @RequestParam("data") final String data,
            @RequestParam("session") final String session,
            final HttpServletRequest request,
            final Authentication authentication)
            throws ServletException {

        final String username = authentication.getName();
        final UserN user = userNService.find(username).orElseThrow(RuntimeException::new);

        final JsonNode json;
        try {
            json = jacksonMapper.readTree(data);
        } catch (IOException e) {
            throw new ServletException("Input not valid json");
        }
        final String credentialId = json.get("id").textValue();
        final String type = json.get("type").textValue();
        final JsonNode makeCredentialResponse = json.get("response");

        final AuthenticatorAttestationResponseN attestation;
        try {
            attestation = new AuthenticatorAttestationResponseN(makeCredentialResponse);
        } catch (ResponseException e) {
            throw new ServletException(e.toString());
        }

        // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support
        // padding.
        final String credentialIdRecoded = Base64.getUrlEncoder().encodeToString(Base64.getUrlDecoder().decode(credentialId));

        final PublicKeyCredentialN cred = new PublicKeyCredentialN(attestation, credentialIdRecoded, type, Base64.getUrlDecoder().decode(credentialId));

        final String domain = (request.isSecure() ? "https://" : "http://") + host;
        final String rpId = host.split(":")[0];
        switch (cred.getAttestationType()) {
            case FIDOU2F:
                u2fServerN.registerCredential(cred, user.getId(), session, domain, rpId);
                break;
            case ANDROIDSAFETYNET:
                androidSafetyNetServerN.registerCredential(cred, user.getId(), session, rpId);
                break;
            case PACKED:
                packedServerN.registerCredential(cred, user.getId(), session, rpId);
                break;
            case NONE:
                break;
        }

        final CredentialStoreN credential = new CredentialStoreN(user.getId(), cred);
        credentialStoreNService.save(credential);

        final PublicKeyCredentialResponseN rsp = new PublicKeyCredentialResponseN(true, "Successfully created credential", null);

        return rsp;
    }

}
