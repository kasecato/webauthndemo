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

import co.nstant.in.cbor.CborException;
import com.github.kasecato.webauthn.server.core.exceptions.ResponseException;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class AuthenticatorData {

    // optional
    AttestationData attData;
    private byte[] rpIdHash;
    private byte flags;
    private int signCount;
    private byte[] extensions;

    public AuthenticatorData(
            final byte[] rpIdHash,
            final byte flags,
            final int signCount,
            final AttestationData attData,
            final byte[] extensions) {

        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = signCount;
        this.attData = attData;
        this.extensions = extensions;
    }

    AuthenticatorData() {
        rpIdHash = new byte[32];
        attData = new AttestationData();
        this.extensions = null;
    }

    AuthenticatorData(
            final byte[] rpIdHash,
            final byte flags,
            final int signCount) {

        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = signCount;
        this.attData = null;
        this.extensions = null;
    }

    /**
     * @param authData
     * @return Decoded AuthenticatorData object
     * @throws ResponseException
     */
    public static AuthenticatorData decode(
            final byte[] authData)
            throws ResponseException {

        if (authData.length < 37) {
            throw new ResponseException("Invalid input");
        }

        int index = 0;
        final byte[] rpIdHash = new byte[32];
        System.arraycopy(authData, 0, rpIdHash, 0, 32);
        index += 32;
        final byte flags = authData[index++];
        final int signCount =
                Ints.fromBytes(authData[index++], authData[index++], authData[index++], authData[index++]);

        final int definedIndex = index;

        AttestationData attData = null;
        // Bit 6 determines whether attestation data was included
        if ((flags & 1 << 6) != 0) {
            final byte[] remainder = new byte[authData.length - index];
            System.arraycopy(authData, index, remainder, 0, authData.length - index);
            try {
                attData = AttestationData.decode(remainder);
            } catch (final CborException e) {
                throw new ResponseException("Error decoding");
            }
        }

        byte[] extensions = null;
        // Bit 7 determines whether extensions are included.
        if ((flags & 1 << 7) != 0) {
            try {
                final int start = definedIndex + attData.encode().length;
                if (authData.length > start) {
                    final byte[] remainder = new byte[authData.length - start];
                    System.arraycopy(authData, start, remainder, 0, authData.length - start);
                    extensions = remainder;
                }
            } catch (final CborException e) {
                throw new ResponseException("Error decoding authenticator extensions");
            }
        }

        return new AuthenticatorData(rpIdHash, flags, signCount, attData, extensions);
    }

    /**
     * @return the rpIdHash
     */
    public byte[] getRpIdHash() {
        return rpIdHash;
    }

    /**
     * @return the flags
     */
    public byte getFlags() {
        return flags;
    }

    /**
     * @return the UP bit of the flags
     */
    public boolean isUP() {
        return (flags & 1) != 0;
    }

    /**
     * @return the UP bit of the flags
     */
    public boolean isUV() {
        return (flags & 1 << 2) != 0;
    }

    /**
     * @return the UP bit of the flags
     */
    public boolean hasAttestationData() {
        return (flags & 1 << 6) != 0;
    }

    /**
     * @return the UP bit of the flags
     */
    public boolean hasExtensionData() {
        return (flags & 1 << 7) != 0;
    }

    /**
     * @return the signCount
     */
    public int getSignCount() {
        return signCount;
    }

    /**
     * @return the attData
     */
    public AttestationData getAttData() {
        return attData;
    }

    /**
     * @return Encoded byte array
     * @throws CborException
     */
    public byte[] encode() throws CborException {
        final byte[] flags = {this.flags};
        final byte[] signCount = ByteBuffer.allocate(4).putInt(this.signCount).array();
        byte[] result;
        if (this.attData != null) {
            final byte[] attData = this.attData.encode();
            result = Bytes.concat(rpIdHash, flags, signCount, attData);
        } else {
            result = Bytes.concat(rpIdHash, flags, signCount);
        }
        if (this.extensions != null) {
            result = Bytes.concat(result, extensions);
        }
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        try {
            if (obj instanceof AuthenticatorData) {
                final AuthenticatorData other = (AuthenticatorData) obj;
                if (flags == other.flags) {
                    if (Arrays.equals(other.rpIdHash, rpIdHash)) {
                        if (signCount == other.signCount) {
                            if (attData == null && other.attData == null) {
                                return true;
                            }
                            if (attData.equals(other.attData)) {
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (final NullPointerException e) {
            return false;
        }
        return false;
    }

}
