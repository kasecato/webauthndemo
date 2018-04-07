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

import com.google.webauthn.springdemo.entities.SessionData;
import com.google.webauthn.springdemo.repositories.SessionDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;

@Service
public class SessionDataService {

    private final SessionDataRepository sessionDataRepository;

    @Autowired
    public SessionDataService(final SessionDataRepository sessionDataRepository) {
        this.sessionDataRepository = sessionDataRepository;
    }

    @Transactional(readOnly = true)
    public Optional<SessionData> findByIdAndUserId(final Long id, final Long userId) {
        return sessionDataRepository.findByIdAndUserId(id, userId);
    }

    @Transactional(rollbackFor = Exception.class)
    public SessionData save(SessionData sessionData) {
        return sessionDataRepository.save(sessionData);
    }

    @Transactional(rollbackFor = Exception.class)
    public void remove(final Long id, final Long userId) {
        sessionDataRepository.deleteByIdAndUserId(id, userId);
    }

    @Transactional(rollbackFor = Exception.class)
    public void removeOldSessions(final Long userId) {
        Date expiryDate = new Date(System.currentTimeMillis() - (1 * 60 * 60 * 1000));
        sessionDataRepository.deleteByUserIdAndCreatedBefore(userId, expiryDate);
    }

}
