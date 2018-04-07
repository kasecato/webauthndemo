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

import co.nstant.in.cbor.CborException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.webauthn.springdemo.exceptions.ResponseException;

import java.io.IOException;
import java.util.Base64;

public class AuthenticatorAttestationResponseN extends AuthenticatorResponseN {

    private final AttestationObject attestationObject;
    private final byte[] attestationObjectBytes;

    public AuthenticatorAttestationResponseN(final byte[] attestationObjectBytes)
            throws ResponseException, CborException {

        attestationObject = AttestationObject.decode(attestationObjectBytes);
        this.attestationObjectBytes = attestationObjectBytes;
    }

    public AuthenticatorAttestationResponseN(
            final JsonNode data)
            throws ResponseException {

        final AttestationResponseJsonN parsedObject;
        try {
            parsedObject = new ObjectMapper().treeToValue(data, AttestationResponseJsonN.class);
        } catch (final JsonProcessingException e) {
            throw new ResponseException("Cannot decode attestation response object");
        }
        setClientDataBytes(Base64.getDecoder().decode(parsedObject.clientDataJSON));

        final byte[] attestationObject = Base64.getDecoder().decode(parsedObject.attestationObject);
        attestationObjectBytes = attestationObject;
        try {
            this.attestationObject = AttestationObject.decode(attestationObject);
        } catch (CborException e) {
            throw new ResponseException("Cannot decode attestation object");
        }

        try {
            setCollectedClientDataN(new ObjectMapper().readValue(getClientDataBytes(), CollectedClientDataN.class));
        } catch (final IOException e) {
            throw new ResponseException("Cannot decode attestation client data object");
        }
    }

    public String encode() {
        final ObjectNode json = JsonNodeFactory.instance.objectNode();
        json.put("clientDataJSON", Base64.getEncoder().encode(getClientDataBytes()));
        try {
            json.put("attestationObject", Base64.getEncoder().encode(attestationObject.encode()));
        } catch (final CborException e) {
            return null;
        }
        return json.asText();
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return attestationObjectBytes;
    }

    private static class AttestationResponseJsonN {

        private String clientDataJSON;
        private String attestationObject;

        public String getClientDataJSON() {
            return clientDataJSON;
        }

        public AttestationResponseJsonN setClientDataJSON(final String clientDataJSON) {
            this.clientDataJSON = clientDataJSON;
            return this;
        }

        public String getAttestationObject() {
            return attestationObject;
        }

        public AttestationResponseJsonN setAttestationObject(final String attestationObject) {
            this.attestationObject = attestationObject;
            return this;
        }
    }

}
