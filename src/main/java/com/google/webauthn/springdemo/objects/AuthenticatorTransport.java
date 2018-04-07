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

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;

public enum AuthenticatorTransport {

    USB("usb"),
    NFC("nfc"),
    BLE("ble");

    private String name;

    AuthenticatorTransport(String name) {
        this.name = name;
    }

    /**
     * @param s
     * @return Transport corresponding to the input string
     */
    public static AuthenticatorTransport decode(final String s) {
        return Arrays.stream(AuthenticatorTransport.values())
                .filter(t -> t.name.equals(s))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(s + " not a valid Transport"));
    }

    @Override
    @JsonValue
    public String toString() {
        return name;
    }

}
