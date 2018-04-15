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

import co.nstant.in.cbor.CborException;
import com.github.kasecato.webauthn.server.core.exceptions.ResponseException;
import com.github.kasecato.webauthn.server.core.objects.AttestationObject;
import com.github.kasecato.webauthn.server.core.objects.AuthenticatorAttestationResponse;
import com.github.kasecato.webauthn.server.core.objects.CredentialPublicKey;
import com.google.webauthn.springdemo.entities.CredentialStore;
import com.google.webauthn.springdemo.entities.User;
import com.google.webauthn.springdemo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.bind.DatatypeConverter;
import java.util.Collection;
import java.util.HashSet;

@RestController
public class RegisteredKeys {

    private final UserService userService;

    @Autowired
    public RegisteredKeys(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping(
            path = "/RegisteredKeys",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected Collection<RegisteredKey> getRegisteredKeys(final Authentication authentication)
            throws CborException, ResponseException {

        final String username = authentication.getName();
        final User user = userService.find(username).orElseThrow(RuntimeException::new);
        final Collection<CredentialStore> savedCreds = user.getRawCredentials();

        final Collection<RegisteredKey> registeredKeys = new HashSet<>();
        for (final CredentialStore c : savedCreds) {
            final AuthenticatorAttestationResponse response = new AuthenticatorAttestationResponse(c.getAttestationObjectBytes());
            final CredentialPublicKey publicKey = response.getAttestationObject().getAuthData().getAttData().getPublicKey();
            final AttestationObject attObj = response.getAttestationObject();

            final RegisteredKey registeredKey = new RegisteredKey(
                    DatatypeConverter.printHexBinary(c.getRawId()),
                    publicKey.toString(),
                    attObj.getAttStmt().getName(),
                    c.getDate().toString(),
                    c.getId()
            );
            registeredKeys.add(registeredKey);
        }
        return registeredKeys;
    }

    private static class RegisteredKey {

        private final String handle;
        private final String publicKey;
        private final String name;
        private final String date;
        private final Long id;

        public RegisteredKey(
                final String handle,
                final String publicKey,
                final String name,
                final String date,
                final Long id) {

            this.handle = handle;
            this.publicKey = publicKey;
            this.name = name;
            this.date = date;
            this.id = id;
        }

        public String getHandle() {
            return handle;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public String getName() {
            return name;
        }

        public String getDate() {
            return date;
        }

        public Long getId() {
            return id;
        }

    }

}
