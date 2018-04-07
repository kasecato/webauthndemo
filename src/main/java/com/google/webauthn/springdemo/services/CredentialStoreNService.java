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

package com.google.webauthn.springdemo.services;

import com.google.webauthn.springdemo.entities.CredentialStoreN;
import com.google.webauthn.springdemo.repositories.CredentialStoreNRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
public class CredentialStoreNService {

    private final CredentialStoreNRepository credentialStoreNRepository;

    @Autowired
    public CredentialStoreNService(final CredentialStoreNRepository credentialStoreNRepository) {
        this.credentialStoreNRepository = credentialStoreNRepository;
    }

    @Transactional(readOnly = true)
    public Set<CredentialStoreN> findByUserId(final Long userId) {
        return credentialStoreNRepository.findByUserId(userId);
    }

    @Transactional(rollbackFor = Exception.class)
    public CredentialStoreN save(final CredentialStoreN credentialStoreN) {
        return credentialStoreNRepository.save(credentialStoreN);
    }

    @Transactional(rollbackFor = Exception.class)
    public CredentialStoreN updateSignCount(final CredentialStoreN credentialStoreN, final int signCount) {
        credentialStoreN.setSignCount(signCount);
        return credentialStoreNRepository.save(credentialStoreN);
    }

    @Transactional(rollbackFor = Exception.class)
    public void delete(final Long id) {
        credentialStoreNRepository.deleteById(id);
    }

}
