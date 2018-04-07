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

import java.util.ArrayList;

public class PublicKeyCredentialDescriptor {

    private final PublicKeyCredentialType type;
    private final byte[] id;
    private final ArrayList<AuthenticatorTransport> transports;

    public PublicKeyCredentialDescriptor(
            final PublicKeyCredentialType type,
            final byte[] id,
            final ArrayList<AuthenticatorTransport> transports) {

        this.type = type;
        this.id = id;
        this.transports = transports;
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public byte[] getId() {
        return id;
    }

    public ArrayList<AuthenticatorTransport> getTransports() {
        return transports;
    }

}
