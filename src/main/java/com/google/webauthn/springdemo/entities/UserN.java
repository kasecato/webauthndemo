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
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.util.Set;

@Entity
@Table(name = "users")
public class UserN {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String nickname;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private boolean enabled;

    @OneToMany(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    private Set<AuthorityN> authoritiesN;

    @OneToMany(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    private Set<CredentialStoreN> credentials;

    public UserN() {
    }

    public Long getId() {
        return id;
    }

    public UserN setId(final Long id) {
        this.id = id;
        return this;
    }

    public String getUsername() {
        return username;
    }

    public UserN setUsername(final String username) {
        this.username = username;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public UserN setPassword(final String password) {
        this.password = password;
        return this;
    }

    public String getNickname() {
        return nickname;
    }

    public UserN setNickname(final String nickname) {
        this.nickname = nickname;
        return this;
    }

    public String getEmail() {
        return email;
    }

    public UserN setEmail(final String email) {
        this.email = email;
        return this;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public UserN setEnabled(final boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public Set<AuthorityN> getAuthoritiesN() {
        return authoritiesN;
    }

    public UserN setAuthoritiesN(final Set<AuthorityN> authoritiesN) {
        this.authoritiesN = authoritiesN;
        return this;
    }

    public Set<CredentialStoreN> getCredentials() {
        return credentials;
    }

    public UserN setCredentials(final Set<CredentialStoreN> credentials) {
        this.credentials = credentials;
        return this;
    }

}
