package com.github.kasecato.webauthn.server.core.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.kasecato.webauthn.server.core.models.CredentialModel;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialsGetTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void assertion() throws Exception {
        final String finishGetAssertJson = objectMapper.readTree(
                new File(getClass().getClassLoader()
                        .getResource("FinishGetAssertionTest_Request_Chrome65.json").getFile())).toString();

        final CredentialModel savedCred = new CredentialsCreateTest().doCreate();
        final long signCountBefore = savedCred.getSignCount();

        final CredentialModel result = CredentialsGet.assertion(
                finishGetAssertJson,
                "dzMJTQgN+8u7TgHK08YOLz0V5CM8Z1eESMB89rSxN1M=",
                Collections.singleton(savedCred));

        assertEquals("wujRudeGT-b85GQO3oNNVWfnNe3SDK3_IvLLuhMIYPi6xFN5c63nAWiA1-_IdgYhDn04n0Onrf-yOWKT6aRoLw==", result.getId());
        assertTrue(signCountBefore < result.getSignCount());
    }

}
