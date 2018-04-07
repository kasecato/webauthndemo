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


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.Base64;
import java.util.Date;

@Entity
@Table(name = "session_data")
public class SessionDataN {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false)
    private String challenge;

    @Column(nullable = false)
    private String origin;

    @Column(nullable = false)
    private Date created;

    public SessionDataN() {
    }

    public SessionDataN(
            final Long userId,
            final byte[] challenge,
            final String origin) {

        this.userId = userId;
        this.challenge = Base64.getEncoder().encodeToString(challenge);
        this.origin = origin;
        this.created = new Date();
    }

    public Long getId() {
        return id;
    }

    public SessionDataN setId(final Long id) {
        this.id = id;
        return this;
    }

    public Long getUserId() {
        return userId;
    }

    public SessionDataN setUserId(final Long userId) {
        this.userId = userId;
        return this;
    }

    public String getChallenge() {
        return challenge;
    }

    public SessionDataN setChallenge(final String challenge) {
        this.challenge = challenge;
        return this;
    }

    public String getOrigin() {
        return origin;
    }

    public SessionDataN setOrigin(final String origin) {
        this.origin = origin;
        return this;
    }

    public Date getCreated() {
        return created;
    }

    public SessionDataN setCreated(final Date created) {
        this.created = created;
        return this;
    }

}
