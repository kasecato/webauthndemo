// Copyright 2018 Google Inc.
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

public class TokenBinding {

    private TokenBindingStatus status;

    private String id;

    public TokenBinding() {
    }

    public TokenBindingStatus getStatus() {
        return status;
    }

    public TokenBinding setStatus(final TokenBindingStatus status) {
        this.status = status;
        return this;
    }

    public String getId() {
        return id;
    }

    public TokenBinding setId(final String id) {
        this.id = id;
        return this;
    }

}
