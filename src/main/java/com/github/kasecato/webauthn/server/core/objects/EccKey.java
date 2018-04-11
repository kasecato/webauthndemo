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

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

public class EccKey extends CredentialPublicKey {

    byte[] x, y;

    int crv;

    EccKey() {
        x = null;
        y = null;
        alg = Algorithm.UNDEFINED;
    }

    public EccKey(
            final Algorithm alg,
            final byte[] x,
            final byte[] y) {

        this.alg = alg;
        this.x = x;
        this.y = y;
    }

    public EccKey(
            final byte[] x,
            final byte[] y) {

        super();
        this.x = x;
        this.y = y;
    }

    @Override
    public boolean equals(final Object obj) {
        try {
            if (obj instanceof EccKey) {
                final EccKey other = (EccKey) obj;
                if (Arrays.equals(x, other.x) && Arrays.equals(y, other.y) && alg == other.alg) {
                    return true;
                }
            }
        } catch (final NullPointerException e) {
        }
        return false;
    }

    @Override
    public byte[] encode() throws CborException {
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final List<DataItem> dataItems =
                new CborBuilder().addMap().put(new UnsignedInteger(KTY_LABEL), new UnsignedInteger(kty))
                        .put(new UnsignedInteger(ALG_LABEL), new NegativeInteger(alg.encodeToInt()))
                        .put(new NegativeInteger(CRV_LABEL), new UnsignedInteger(crv))
                        .put(new NegativeInteger(X_LABEL), new ByteString(x))
                        .put(new NegativeInteger(Y_LABEL), new ByteString(y)).end().build();
        new CborEncoder(output).encode(dataItems);
        return output.toByteArray();
    }

    @Override
    public String toString() {
        final StringBuilder b = new StringBuilder();
        b.append("alg:");
        b.append(alg.toReadableString());
        b.append(" x:");
        b.append(DatatypeConverter.printHexBinary(x));
        b.append(" y:");
        b.append(DatatypeConverter.printHexBinary(y));
        return b.toString();
    }

    public byte[] getX() {
        return x;
    }

    public byte[] getY() {
        return y;
    }

}
