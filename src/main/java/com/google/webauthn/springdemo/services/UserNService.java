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

import com.google.webauthn.springdemo.entities.UserN;
import com.google.webauthn.springdemo.repositories.UserNRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserNService {

    private final UserNRepository userNRepository;

    public UserNService(final UserNRepository userNRepository) {
        this.userNRepository = userNRepository;
    }

    public Optional<UserN> find(final String username) {
        return userNRepository.findByUsername(username);
    }

}
