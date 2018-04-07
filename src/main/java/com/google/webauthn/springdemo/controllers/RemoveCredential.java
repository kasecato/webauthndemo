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

import com.google.webauthn.springdemo.services.CredentialStoreService;
import com.google.webauthn.springdemo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
public class RemoveCredential {

    private final UserService userService;
    private final CredentialStoreService credentialStoreService;

    @Autowired
    public RemoveCredential(
            final UserService userService,
            final CredentialStoreService credentialStoreService) {

        this.userService = userService;
        this.credentialStoreService = credentialStoreService;
    }

    @RequestMapping(
            path = "/RemoveCredential",
            method = {RequestMethod.POST, RequestMethod.GET},
            produces = MediaType.APPLICATION_JSON_VALUE)
    protected Map<String, String> postRemoveCredential(
            final Long credentialId,
            final Authentication authentication) {

        final String username = authentication.getName();
        userService.find(username).orElseThrow(RuntimeException::new);
        credentialStoreService.delete(credentialId);

        return Collections.emptyMap();
    }

}
