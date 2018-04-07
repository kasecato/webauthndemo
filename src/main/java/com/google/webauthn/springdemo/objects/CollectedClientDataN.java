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

package com.google.webauthn.springdemo.objects;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.webauthn.springdemo.crypto.Crypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

public class CollectedClientDataN {

    private String type;
    private String challenge;
    private String origin;
    private String hashAlgorithm;
    private String tokenBinding;
    // private TokenBindingN tokenBinding;
    private HashMap<String, Object> clientExtensions;
    private HashMap<String, Object> authenticatorExtensions;

    public CollectedClientDataN() {
    }

    /**
     * @param json
     * @return Decoded CollectedClientData object
     */
    public static CollectedClientDataN decode(String json) {
        final ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(json, CollectedClientDataN.class);
        } catch (final IOException e) {
            return null;
        }
    }

    /**
     * @return json encoded representation of CollectedClientData
     */
    public String encode() {
        final ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (final JsonProcessingException e) {
            return null;
        }
    }

    public byte[] getHash() {
        final String json = encode();
        try {
            return Crypto.digest(json.getBytes(), hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            return Crypto.sha256Digest(json.getBytes());
        }
    }

    @Override
    public boolean equals(Object obj) {
        try {
            if (obj instanceof CollectedClientDataN) {
                final CollectedClientDataN other = (CollectedClientDataN) obj;
                if ((getChallenge() == other.challenge) || getChallenge().equals(other.challenge)) {
                    if ((getOrigin() == other.origin) || getOrigin().equals(other.origin)) {
                        if ((getHashAlgorithm() == other.hashAlgorithm) || getHashAlgorithm().equals(other.hashAlgorithm)) {
                            if ((getTokenBinding() == other.tokenBinding)
                                    || (getTokenBinding().equals(other.tokenBinding))) {
                                if ((getType() == other.type) || (getType().equals(other.type))) {
                                    if ((getClientExtensions() == other.clientExtensions)
                                            || (getClientExtensions().equals(other.clientExtensions))) {
                                        if ((getAuthenticatorExtensions() == other.authenticatorExtensions)
                                                || (getAuthenticatorExtensions().equals(other.authenticatorExtensions))) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (NullPointerException e) {
            // Fall out
        }
        return false;
    }

    public String getType() {
        return type;
    }

    public CollectedClientDataN setType(final String type) {
        this.type = type;
        return this;
    }

    public String getChallenge() {
        return challenge;
    }

    public CollectedClientDataN setChallenge(final String challenge) {
        this.challenge = challenge;
        return this;
    }

    public String getOrigin() {
        return origin;
    }

    public CollectedClientDataN setOrigin(final String origin) {
        this.origin = origin;
        return this;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public CollectedClientDataN setHashAlgorithm(final String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    public String getTokenBinding() {
        return tokenBinding;
    }

    public CollectedClientDataN setTokenBinding(final String tokenBinding) {
        this.tokenBinding = tokenBinding;
        return this;
    }

    public HashMap<String, Object> getClientExtensions() {
        return clientExtensions;
    }

    public CollectedClientDataN setClientExtensions(final HashMap<String, Object> clientExtensions) {
        this.clientExtensions = clientExtensions;
        return this;
    }

    public HashMap<String, Object> getAuthenticatorExtensions() {
        return authenticatorExtensions;
    }

    public CollectedClientDataN setAuthenticatorExtensions(final HashMap<String, Object> authenticatorExtensions) {
        this.authenticatorExtensions = authenticatorExtensions;
        return this;
    }

}
