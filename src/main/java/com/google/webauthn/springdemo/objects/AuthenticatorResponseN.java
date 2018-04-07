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

public class AuthenticatorResponseN {

    private byte[] clientDataBytes;
    private CollectedClientDataN collectedClientDataN;

    public AuthenticatorResponseN() {
    }

    public byte[] getClientDataBytes() {
        return clientDataBytes;
    }

    public AuthenticatorResponseN setClientDataBytes(final byte[] clientDataBytes) {
        this.clientDataBytes = clientDataBytes;
        return this;
    }

    public CollectedClientDataN getCollectedClientDataN() {
        return collectedClientDataN;
    }

    public AuthenticatorResponseN setCollectedClientDataN(final CollectedClientDataN collectedClientDataN) {
        this.collectedClientDataN = collectedClientDataN;
        return this;
    }

}
