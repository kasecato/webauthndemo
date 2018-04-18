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

package com.github.kasecato.webauthn.server.core.objects;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;

public enum TokenBindingStatus {

    PLATFORM("present"),
    SUPPORTED("supported"),
    NOT_SUPPORTED("not-supported");

    private final String name;

    TokenBindingStatus(String name) {
        this.name = name;
    }

    /**
     * @param s
     * @return TokenBindingStatus corresponding to the input string
     */
    public static TokenBindingStatus decode(final String s) {
        return Arrays.stream(TokenBindingStatus.values())
                .filter(a -> a.name.equals(s))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(s + " not a valid TokenBindingStatus"));
    }

    @Override
    @JsonValue
    public String toString() {
        return name;
    }

}
