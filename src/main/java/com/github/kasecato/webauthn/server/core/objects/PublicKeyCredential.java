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

package com.github.kasecato.webauthn.server.core.objects;

public class PublicKeyCredential {

    private String id;
    private String type;
    private byte[] rawId;
    private AuthenticatorResponse response;

    public PublicKeyCredential(
            final String id,
            final String type,
            final byte[] rawId,
            final AuthenticatorResponse response) {

        this.id = id;
        this.type = type;
        this.rawId = rawId;
        this.response = response;
    }

    public AttestationStatementEnum getAttestationType() {
        try {
            final AuthenticatorAttestationResponse attRsp = (AuthenticatorAttestationResponse) response;
            final AttestationStatement attStmt = attRsp.getAttestationObject().getAttStmt();
            if (attStmt instanceof AndroidSafetyNetAttestationStatement) {
                return AttestationStatementEnum.ANDROIDSAFETYNET;
            } else if (attStmt instanceof FidoU2fAttestationStatement) {
                return AttestationStatementEnum.FIDOU2F;
            } else if (attStmt instanceof PackedAttestationStatement) {
                return AttestationStatementEnum.PACKED;
            } else if (attStmt instanceof NoneAttestationStatement) {
                return AttestationStatementEnum.NONE;
            }
        } catch (ClassCastException e) {
            return null;
        }
        return null;
    }

    public String getId() {
        return id;
    }

    public PublicKeyCredential setId(final String id) {
        this.id = id;
        return this;
    }

    public String getType() {
        return type;
    }

    public PublicKeyCredential setType(final String type) {
        this.type = type;
        return this;
    }

    public byte[] getRawId() {
        return rawId;
    }

    public PublicKeyCredential setRawId(final byte[] rawId) {
        this.rawId = rawId;
        return this;
    }

    public AuthenticatorResponse getResponse() {
        return response;
    }

    public PublicKeyCredential setResponse(final AuthenticatorResponse response) {
        this.response = response;
        return this;
    }

}
