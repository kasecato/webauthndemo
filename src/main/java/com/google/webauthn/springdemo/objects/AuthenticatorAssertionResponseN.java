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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.webauthn.springdemo.exceptions.ResponseException;

import java.io.IOException;
import java.util.Base64;

public class AuthenticatorAssertionResponseN extends AuthenticatorResponseN {

    private final AuthenticatorData authenticatorData;
    private final byte[] authenticatorDataBytes;
    private final byte[] signatureBytes;
    private final byte[] userHandleBytes;

    public AuthenticatorAssertionResponseN(
            final JsonNode data)
            throws ResponseException {

        final ObjectMapper objectMapper = new ObjectMapper();
        final AssertionResponseJsonN parsedObject;
        try {
            parsedObject = objectMapper.treeToValue(data, AssertionResponseJsonN.class);
        } catch (IOException e) {
            throw new ResponseException("Response format incorrect");
        }
        authenticatorDataBytes = Base64.getDecoder().decode(parsedObject.authenticatorData);
        signatureBytes = Base64.getDecoder().decode(parsedObject.signature);
        userHandleBytes = Base64.getDecoder().decode(parsedObject.userHandle);
        setClientDataBytes(Base64.getDecoder().decode(parsedObject.clientDataJSON));

        try {
            setCollectedClientDataN(objectMapper.readValue(getClientDataBytes(), CollectedClientDataN.class));
        } catch (IOException e) {
            throw new ResponseException("Response format incorrect");
        }

        authenticatorData = AuthenticatorData.decode(authenticatorDataBytes);
    }

    public AuthenticatorData getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getAuthenticatorDataBytes() {
        return authenticatorDataBytes;
    }

    public byte[] getSignatureBytes() {
        return signatureBytes;
    }

    public byte[] getUserHandleBytes() {
        return userHandleBytes;
    }

    private static class AssertionResponseJsonN {
        private String clientDataJSON;
        private String authenticatorData;
        private String signature;
        private String userHandle;

        public String getClientDataJSON() {
            return clientDataJSON;
        }

        public AssertionResponseJsonN setClientDataJSON(final String clientDataJSON) {
            this.clientDataJSON = clientDataJSON;
            return this;
        }

        public String getAuthenticatorData() {
            return authenticatorData;
        }

        public AssertionResponseJsonN setAuthenticatorData(final String authenticatorData) {
            this.authenticatorData = authenticatorData;
            return this;
        }

        public String getSignature() {
            return signature;
        }

        public AssertionResponseJsonN setSignature(final String signature) {
            this.signature = signature;
            return this;
        }

        public String getUserHandle() {
            return userHandle;
        }

        public AssertionResponseJsonN setUserHandle(final String userHandle) {
            this.userHandle = userHandle;
            return this;
        }
    }

}
