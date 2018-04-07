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

public class AuthenticatorSelectionCriteria {

    private final AuthenticatorAttachment authenticatorAttachment;
    private final boolean requireResidentKey;
    private final UserVerificationRequirement userVerification;

    public AuthenticatorSelectionCriteria() {
        authenticatorAttachment = null;
        requireResidentKey = false;
        userVerification = UserVerificationRequirement.PREFERRED;
    }

    public AuthenticatorAttachment getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

}
