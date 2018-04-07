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
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "authorities")
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "user_id", nullable = false, unique = true)
    private Long userId;
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private AuthorityType authority;

    public Authority() {
    }

    public Long getId() {
        return id;
    }

    public Authority setId(final Long id) {
        this.id = id;
        return this;
    }

    public Long getUserId() {
        return userId;
    }

    public Authority setUserId(final Long userId) {
        this.userId = userId;
        return this;
    }

    public AuthorityType getAuthority() {
        return authority;
    }

    public Authority setAuthority(final AuthorityType authority) {
        this.authority = authority;
        return this;
    }

    public enum AuthorityType {
        ROLE_USER,
        ROLE_ADMIN,
    }

}
