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
import com.google.common.primitives.Bytes;
import com.google.webauthn.springdemo.exceptions.ResponseException;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Object representation of the attestation data
 */
public class AttestationData {

    private byte[] aaguid;
    private byte[] credentialId;
    private CredentialPublicKey publicKey;

    public AttestationData() {
        aaguid = new byte[16];
        credentialId = new byte[]{};
        publicKey = new EccKey();
    }

    /**
     * Decodes the input byte array into the AttestationData object
     *
     * @param data
     * @return AttestationData object created from the byte sequence
     * @throws ResponseException
     * @throws CborException
     */
    public static AttestationData decode(final byte[] data)
            throws ResponseException, CborException {

        final AttestationData result = new AttestationData();
        int index = 0;
        if (data.length < 18)
            throw new ResponseException("Invalid input");
        System.arraycopy(data, 0, result.aaguid, 0, 16);
        index += 16;

        int length = (data[index++] << 8) & 0xFF;
        length += data[index++] & 0xFF;

        result.credentialId = new byte[length];
        System.arraycopy(data, index, result.credentialId, 0, length);
        index += length;

        final byte[] cbor = new byte[data.length - index];
        System.arraycopy(data, index, cbor, 0, data.length - index);
        result.publicKey = CredentialPublicKey.decode(cbor);

        return result;
    }

    /**
     * @return Encoded byte array created from AttestationData object
     * @throws CborException
     */
    public byte[] encode() throws CborException {
        return Bytes.concat(aaguid,
                ByteBuffer.allocate(2).putShort((short) credentialId.length).array(), credentialId,
                publicKey.encode());
    }

    /**
     *
     */
    @Override
    public boolean equals(final Object obj) {
        try {
            if (obj instanceof AttestationData) {
                final AttestationData other = (AttestationData) obj;
                if (Arrays.equals(other.aaguid, aaguid) && Arrays.equals(credentialId, other.credentialId)
                        && ((publicKey == null && other.publicKey == null)
                        || (publicKey.equals(other.publicKey)))) {
                    return true;
                }
            }
        } catch (final NullPointerException e) {
            return false;
        }
        return false;
    }

    public byte[] getAaguid() {
        return aaguid;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public CredentialPublicKey getPublicKey() {
        return publicKey;
    }

}
