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

package com.google.webauthn.springdemo.controllers;

import com.google.webauthn.springdemo.entities.User;
import com.google.webauthn.springdemo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class Home {

    private final UserService userService;

    @Autowired
    public Home(
            final UserService userService) {

        this.userService = userService;
    }

    @RequestMapping(
            path = "/",
            method = {RequestMethod.POST, RequestMethod.GET})
    protected String getHome(
            final Authentication authentication,
            final Model model) {

        final String username = authentication.getName();
        final User user = userService.find(username).orElseThrow(RuntimeException::new);
        final String nickname = user.getNickname();
        final String logoutUrl = "/logout";

        model.addAttribute("nickname", nickname);
        model.addAttribute("logoutUrl", logoutUrl);

        return "index";
    }

}
