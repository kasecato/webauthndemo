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

import com.github.kasecato.webauthn.server.core.exceptions.ResponseException;
import com.google.webauthn.springdemo.entities.CredentialStore;
import com.google.webauthn.springdemo.repositories.CredentialStoreRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

@Service
public class CredentialStoreService {

    private final CredentialStoreRepository credentialStoreRepository;

    @Autowired
    public CredentialStoreService(final CredentialStoreRepository credentialStoreRepository) {
        this.credentialStoreRepository = credentialStoreRepository;
    }

    @Transactional(readOnly = true)
    public Set<CredentialStore> findByUserId(final Long userId) {
        return credentialStoreRepository.findByUserId(userId);
    }

    @Transactional(readOnly = true)
    public Optional<CredentialStore> findByPublicKeyCredentialId(final String publicKeyCredentialId) {
        return credentialStoreRepository.findByPublicKeyCredentialId(publicKeyCredentialId);
    }

    @Transactional(rollbackFor = Exception.class)
    public CredentialStore save(final CredentialStore credentialStore) {
        return credentialStoreRepository.save(credentialStore);
    }

    @Transactional(rollbackFor = Exception.class)
    public CredentialStore updateSignCount(final CredentialStore credentialStore, final int signCount) {
        credentialStore.setSignCount(signCount);
        return credentialStoreRepository.save(credentialStore);
    }

    @Transactional(rollbackFor = Exception.class)
    public void updateSignCount(
            final String publicKeyCredentialId,
            final int signCount)
            throws ResponseException {

        findByPublicKeyCredentialId(publicKeyCredentialId)
                .map(c -> c.setSignCount(signCount))
                .map(c -> save(c))
                .orElseThrow(() -> new ResponseException("The credential not found"));
    }

    @Transactional(rollbackFor = Exception.class)
    public void delete(final Long id) {
        credentialStoreRepository.deleteById(id);
    }

}
