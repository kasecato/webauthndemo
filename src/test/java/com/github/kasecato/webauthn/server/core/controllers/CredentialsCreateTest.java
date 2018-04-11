package com.github.kasecato.webauthn.server.core.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.kasecato.webauthn.server.core.models.CredentialModel;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialsCreateTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void create() throws Exception {
        final CredentialModel result = doCreate();
        assertEquals("wujRudeGT-b85GQO3oNNVWfnNe3SDK3_IvLLuhMIYPi6xFN5c63nAWiA1-_IdgYhDn04n0Onrf-yOWKT6aRoLw==", result.getId());
    }

    public CredentialModel doCreate() throws Exception {
        final String finishMakeCredJson = objectMapper.readTree(
                new File(getClass().getClassLoader()
                        .getResource("FinishMakeCredentialTest_Request_Chrome65.json").getFile())).toString();

        return CredentialsCreate.create(
                "localhost",
                finishMakeCredJson,
                "OkT8IA3R+yfLJmKMkQR8awmnHgwsT4p7LvPXwuDJiBk=",
                Collections.emptySet());
    }

}
