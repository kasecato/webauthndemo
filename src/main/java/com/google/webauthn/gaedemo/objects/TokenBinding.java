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

package com.google.webauthn.gaedemo.objects;

import java.util.Objects;

public class TokenBinding {
  TokenBindingStatus status;
  String id;

  public TokenBinding() {
  }

  /**
   * @param status
   * @param id
   */
  public TokenBinding(TokenBindingStatus status, String id) {
    this.status = status;
    this.id = id;
  }

  /**
   * @return the status
   */
  public TokenBindingStatus getStatus() {
    return status;
  }

  /**
   * @return the id
   */
  public String getId() {
    return id;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj instanceof TokenBinding) {
      TokenBinding other = (TokenBinding) obj;
      if (Objects.equals(status, other.status)) {
        if (Objects.equals(id, other.id)) {
          return true;
        }
      }
    }
    return false;
  }
}
