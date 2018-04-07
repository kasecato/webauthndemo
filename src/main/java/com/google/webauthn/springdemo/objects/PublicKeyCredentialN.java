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

public class PublicKeyCredentialN {
    public AuthenticatorResponseN response;
    private String id;
    private String type;
    private byte[] rawId;

    public PublicKeyCredentialN(
            final AuthenticatorResponseN response,
            final String id,
            final String type,
            final byte[] rawId) {

        this.response = response;
        this.id = id;
        this.type = type;
        this.rawId = rawId;
    }

    public AttestationStatementEnum getAttestationType() {
        try {
            final AuthenticatorAttestationResponseN attRsp = (AuthenticatorAttestationResponseN) response;
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

    public AuthenticatorResponseN getResponse() {
        return response;
    }

    public PublicKeyCredentialN setResponse(final AuthenticatorResponseN response) {
        this.response = response;
        return this;
    }

    public String getId() {
        return id;
    }

    public PublicKeyCredentialN setId(final String id) {
        this.id = id;
        return this;
    }

    public String getType() {
        return type;
    }

    public PublicKeyCredentialN setType(final String type) {
        this.type = type;
        return this;
    }

    public byte[] getRawId() {
        return rawId;
    }

    public PublicKeyCredentialN setRawId(final byte[] rawId) {
        this.rawId = rawId;
        return this;
    }

}
