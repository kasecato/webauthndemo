/*
 * Copyright 2017 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package com.google.webauthn.springdemo.crypto;

import com.google.common.primitives.Bytes;
import com.google.webauthn.springdemo.exceptions.WebAuthnException;
import com.google.webauthn.springdemo.objects.EccKey;
import com.google.webauthn.springdemo.objects.RsaKey;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

public class Crypto {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] sha256Digest(final byte[] input) {
        final SHA256Digest digest = new SHA256Digest();
        digest.update(input, 0, input.length);
        final byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    public static byte[] digest(final byte[] input, final String alg) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance(alg);
        return digest.digest(input);
    }

    public static boolean verifySignature(final PublicKey publicKey, final byte[] signedBytes, final byte[] signature)
            throws WebAuthnException {
        try {
            final Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA");
            ecdsaSignature.initVerify(publicKey);
            ecdsaSignature.update(signedBytes);
            return ecdsaSignature.verify(signature);
        } catch (final InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            throw new WebAuthnException("Error when verifying signature", e);
        }
    }

    // TODO add test for this.
    public static boolean verifySignature(final X509Certificate attestationCertificate, final byte[] signedBytes,
                                          final byte[] signature) throws WebAuthnException {
        return verifySignature(attestationCertificate.getPublicKey(), signedBytes, signature);
    }

    public static boolean verifySignature(final X509Certificate attestationCertificate, final byte[] signedBytes,
                                          byte[] signature, String signatureAlgorithm) throws WebAuthnException {
        return verifySignature(attestationCertificate.getPublicKey(), signedBytes, signature,
                signatureAlgorithm);
    }

    public static boolean verifySignature(final PublicKey publicKey, final byte[] message, final byte[] signature,
                                          final String signatureAlgorithm) throws WebAuthnException {
        if (signatureAlgorithm == null || signatureAlgorithm.isEmpty()) {
            throw new WebAuthnException("Signature algorithm is null or empty");
        }
        try {
            final Signature sig = Signature.getInstance(signatureAlgorithm);
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (final NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new WebAuthnException("Error when verifying signature", e);
        }
    }

    public static PublicKey decodePublicKey(final byte[] x, final byte[] y) throws WebAuthnException {
        try {
            final X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            final ECPoint point;
            try {
                final byte[] encodedPublicKey = Bytes.concat(new byte[]{0x04}, x, y);
                point = curve.getCurve().decodePoint(encodedPublicKey);
            } catch (RuntimeException e) {
                throw new WebAuthnException("Couldn't parse user public key", e);
            }

            return KeyFactory.getInstance("ECDSA").generatePublic(new ECPublicKeySpec(point,
                    new ECParameterSpec(curve.getCurve(), curve.getG(), curve.getN(), curve.getH())));
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new WebAuthnException("Error when decoding public key", e);
        }
    }

    public static PublicKey getRSAPublicKey(final RsaKey rsaKey) throws WebAuthnException {
        final BigInteger modulus = new BigInteger(rsaKey.getN());
        final BigInteger publicExponent = new BigInteger(rsaKey.getE());
        try {
            return getRSAPublicKey(modulus, publicExponent);
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new WebAuthnException("Error when generate RSA public key", e);
        }
    }

    public static PublicKey getECPublicKey(final EccKey eccKey) throws WebAuthnException {
        final BigInteger x = new BigInteger(eccKey.getX());
        final BigInteger y = new BigInteger(eccKey.getY());
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
        final EcdsaUsingShaAlgorithm algorithm =
                (EcdsaUsingShaAlgorithm) AlgorithmIdentifierMapper.get(eccKey.getAlg());
        final String curveName = algorithm.getCurveName();
        try {
            return getECPublicKey(w, curveName);
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new WebAuthnException("Error when generate EC public key", e);
        }
    }

    public static PublicKey getRSAPublicKey(final BigInteger n, final BigInteger e)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeySpec keySpec = new RSAPublicKeySpec(n, e);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static PublicKey getECPublicKey(final java.security.spec.ECPoint w, final String stdCurveName)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(stdCurveName);
        final java.security.spec.ECParameterSpec params = new ECNamedCurveSpec(parameterSpec.getName(),
                parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH(),
                parameterSpec.getSeed());
        final KeySpec keySpec = new java.security.spec.ECPublicKeySpec(w, params);
        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }
}
