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

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import com.google.webauthn.springdemo.exceptions.ResponseException;

import java.io.ByteArrayOutputStream;
import java.util.List;

public class AttestationObject {

    private AuthenticatorData authData;
    private String fmt;
    private AttestationStatement attStmt;

    /**
     * @param attestationObject
     * @return AttestationObject created from the provided byte array
     * @throws CborException
     * @throws ResponseException
     */
    public static AttestationObject decode(
            final byte[] attestationObject)
            throws CborException, ResponseException {

        final AttestationObject result = new AttestationObject();
        final List<DataItem> dataItems = CborDecoder.decode(attestationObject);

        if (dataItems.size() == 1 && dataItems.get(0) instanceof Map) {
            DataItem attStmt = null;
            final Map attObjMap = (Map) dataItems.get(0);
            for (final DataItem key : attObjMap.getKeys()) {
                if (key instanceof UnicodeString) {
                    if (((UnicodeString) key).getString().equals("fmt")) {
                        final UnicodeString value = (UnicodeString) attObjMap.get(key);
                        result.fmt = value.getString();
                    }
                    if (((UnicodeString) key).getString().equals("authData")) {
                        final byte[] authData = ((ByteString) attObjMap.get(key)).getBytes();
                        result.authData = AuthenticatorData.decode(authData);
                    }
                    if (((UnicodeString) key).getString().equals("attStmt")) {
                        attStmt = attObjMap.get(key);
                    }
                }
            }

            if (attStmt != null) {
                result.attStmt = AttestationStatement.decode(result.fmt, attStmt);
            }

        }
        return result;
    }

    /**
     * @return Encoded byte array containing AttestationObject data
     * @throws CborException
     */
    public byte[] encode() throws CborException {
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final List<DataItem> cbor =
                new CborBuilder().addMap().put("fmt", fmt).put("authData", authData.encode())
                        .put(new UnicodeString("attStmt"), attStmt.encode()).end().build();
        new CborEncoder(output).encode(cbor);
        return output.toByteArray();
    }

    public AuthenticatorData getAuthData() {
        return authData;
    }

    public String getFmt() {
        return fmt;
    }

    public AttestationStatement getAttStmt() {
        return attStmt;
    }

}
