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

package com.google.webauthn.springdemo.objects;

public class PublicKeyCredentialParametersN {

    private final PublicKeyCredentialType type;
    private final Algorithm alg;

    public PublicKeyCredentialParametersN(
            final PublicKeyCredentialType type,
            final Algorithm alg) {

        this.type = type;
        this.alg = alg;
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public Algorithm getAlg() {
        return alg;
    }

}
