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

import com.google.webauthn.springdemo.entities.SessionDataN;
import com.google.webauthn.springdemo.repositories.SessionDataNRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;

@Service
public class SessionDataNService {

    private final SessionDataNRepository sessionDataNRepository;

    @Autowired
    public SessionDataNService(final SessionDataNRepository sessionDataNRepository) {
        this.sessionDataNRepository = sessionDataNRepository;
    }

    @Transactional(readOnly = true)
    public Optional<SessionDataN> findByIdAndUserId(final Long id, final Long userId) {
        return sessionDataNRepository.findByIdAndUserId(id, userId);
    }

    @Transactional(rollbackFor = Exception.class)
    public SessionDataN save(SessionDataN sessionDataN) {
        return sessionDataNRepository.save(sessionDataN);
    }

    @Transactional(rollbackFor = Exception.class)
    public void remove(final Long id, final Long userId) {
        sessionDataNRepository.deleteByIdAndUserId(id, userId);
    }

    @Transactional(rollbackFor = Exception.class)
    public void removeOldSessions(final Long userId) {
        Date expiryDate = new Date(System.currentTimeMillis() - (1 * 60 * 60 * 1000));
        sessionDataNRepository.deleteByUserIdAndCreatedBefore(userId, expiryDate);
    }

}
