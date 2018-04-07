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

import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import com.google.webauthn.springdemo.exceptions.ResponseException;

import java.util.Arrays;

/**
 * Object representation of the Android SafetyNet attestation statement
 */
public class AndroidSafetyNetAttestationStatement extends AttestationStatement {

    private String ver;
    private byte[] response;

    /**
     * Decodes a cbor representation of an AndroidSafetyNetAttestationStatement into the object
     * representation
     *
     * @param attStmt Cbor DataItem representation of the attestation statement to decode
     * @return Decoded AndroidSafetyNetAttestationStatement
     * @throws ResponseException Input was not a valid AndroidSafetyNetAttestationStatement DataItem
     */
    public static AndroidSafetyNetAttestationStatement decode(final DataItem attStmt)
            throws ResponseException {

        final AndroidSafetyNetAttestationStatement result = new AndroidSafetyNetAttestationStatement();
        final Map given = (Map) attStmt;
        for (final DataItem data : given.getKeys()) {
            if (data instanceof UnicodeString) {
                if (((UnicodeString) data).getString().equals("ver")) {
                    final UnicodeString version = (UnicodeString) given.get(data);
                    result.ver = version.getString();
                } else if (((UnicodeString) data).getString().equals("response")) {
                    result.response = ((ByteString) (given.get(data))).getBytes();
                }
            }
        }
        if (result.response == null || result.ver == null)
            throw new ResponseException("Invalid JWT Cbor");
        return result;
    }

    @Override
    DataItem encode() {
        final Map map = new Map();
        map.put(new UnicodeString("ver"), new UnicodeString(ver));
        map.put(new UnicodeString("response"), new ByteString(response));
        return map;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof AndroidSafetyNetAttestationStatement) {
            final AndroidSafetyNetAttestationStatement other = (AndroidSafetyNetAttestationStatement) obj;
            if (ver == other.ver || ((ver != null && other.ver != null) && ver.equals(other.ver))) {
                if (Arrays.equals(response, other.response)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public String getName() {
        return "Android SafetyNet";
    }

    public String getVer() {
        return ver;
    }

    public byte[] getResponse() {
        return response;
    }

}
