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

package com.google.webauthn.springdemo.entities;

import com.google.webauthn.springdemo.objects.AuthenticatorAttestationResponse;
import com.google.webauthn.springdemo.objects.PublicKeyCredential;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.Date;

@Entity
@Table(name = "credential")
public class CredentialStore {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "date", nullable = false)
    private Date date;

    @Column(name = "sign_count", nullable = false)
    private Integer signCount;

    @Column(name = "public_key_credential_id", nullable = false)
    private String publicKeyCredentialId;

    @Column(name = "public_key_credential_type", nullable = false)
    private String publicKeyCredentialType;

    @Column(name = "raw_id", nullable = false)
    private byte[] rawId;

    @Column(name = "attestation_object_bytes", nullable = false)
    private byte[] attestationObjectBytes;

    public CredentialStore() {
    }

    public CredentialStore(
            final Long userId,
            final PublicKeyCredential publicKeyCredential) {

        this.userId = userId;
        this.date = new Date();
        this.signCount = 0;
        this.publicKeyCredentialId = publicKeyCredential.getId();
        this.publicKeyCredentialType = publicKeyCredential.getType();
        this.rawId = publicKeyCredential.getRawId();
        this.attestationObjectBytes = ((AuthenticatorAttestationResponse) publicKeyCredential.getResponse()).getAttestationObjectBytes();
    }

    public Long getId() {
        return id;
    }

    public CredentialStore setId(final Long id) {
        this.id = id;
        return this;
    }

    public Long getUserId() {
        return userId;
    }

    public CredentialStore setUserId(final Long userId) {
        this.userId = userId;
        return this;
    }

    public Date getDate() {
        return date;
    }

    public CredentialStore setDate(final Date date) {
        this.date = date;
        return this;
    }

    public Integer getSignCount() {
        return signCount;
    }

    public CredentialStore setSignCount(final Integer signCount) {
        this.signCount = signCount;
        return this;
    }

    public String getPublicKeyCredentialId() {
        return publicKeyCredentialId;
    }

    public CredentialStore setPublicKeyCredentialId(final String publicKeyCredentialId) {
        this.publicKeyCredentialId = publicKeyCredentialId;
        return this;
    }

    public String getPublicKeyCredentialType() {
        return publicKeyCredentialType;
    }

    public CredentialStore setPublicKeyCredentialType(final String publicKeyCredentialType) {
        this.publicKeyCredentialType = publicKeyCredentialType;
        return this;
    }

    public byte[] getRawId() {
        return rawId;
    }

    public CredentialStore setRawId(final byte[] rawId) {
        this.rawId = rawId;
        return this;
    }

    public byte[] getAttestationObjectBytes() {
        return attestationObjectBytes;
    }

    public CredentialStore setAttestationObjectBytes(final byte[] attestationObjectBytes) {
        this.attestationObjectBytes = attestationObjectBytes;
        return this;
    }

}
