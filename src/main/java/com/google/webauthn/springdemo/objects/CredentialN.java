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

import java.util.Date;

public class CredentialN {

    private Long id;

    private Long userId;

    private Date date;

    private Integer signCount;

    private PublicKeyCredential publicKeyCredential;

    public CredentialN(
            final Long userId,
            final PublicKeyCredential publicKeyCredential) {

        this.userId = userId;
        this.date = new Date();
        this.signCount = 0;
        this.publicKeyCredential = publicKeyCredential;
    }

    public Long getId() {
        return id;
    }

    public CredentialN setId(final Long id) {
        this.id = id;
        return this;
    }

    public Long getUserId() {
        return userId;
    }

    public CredentialN setUserId(final Long userId) {
        this.userId = userId;
        return this;
    }

    public Date getDate() {
        return date;
    }

    public CredentialN setDate(final Date date) {
        this.date = date;
        return this;
    }

    public Integer getSignCount() {
        return signCount;
    }

    public CredentialN setSignCount(final Integer signCount) {
        this.signCount = signCount;
        return this;
    }

    public PublicKeyCredential getPublicKeyCredential() {
        return publicKeyCredential;
    }

    public CredentialN setPublicKeyCredential(final PublicKeyCredential publicKeyCredential) {
        this.publicKeyCredential = publicKeyCredential;
        return this;
    }

}
