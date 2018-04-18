package com.github.kasecato.webauthn.server.core.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.kasecato.webauthn.server.core.models.CredentialModel;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.Collections;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialsGetTest {

    @ParameterizedTest
    @MethodSource("jsonProvider")
    void assertion(
            final String browser,
            final String challengeGet,
            final String challengeAssert,
            final String credentialId)
            throws Exception {

        final String finishGetAssertJson = new ObjectMapper().readTree(
                new File(getClass().getClassLoader()
                        .getResource(String.format("FinishGetAssertionTest_Request_%s.json", browser)).getFile())).toString();

        final CredentialModel savedCred = new CredentialsCreateTest().doCreate(browser, challengeGet);
        final long signCountBefore = savedCred.getSignCount();

        final CredentialModel result = CredentialsGet.assertion(
                finishGetAssertJson,
                challengeAssert,
                Collections.singleton(savedCred));

        assertEquals(credentialId, result.getId());
        assertTrue(signCountBefore < result.getSignCount());
    }

    static Stream<Arguments> jsonProvider() {
        return Stream.of(
                Arguments.of("Chrome65", "OkT8IA3R+yfLJmKMkQR8awmnHgwsT4p7LvPXwuDJiBk=", "dzMJTQgN+8u7TgHK08YOLz0V5CM8Z1eESMB89rSxN1M=", "wujRudeGT-b85GQO3oNNVWfnNe3SDK3_IvLLuhMIYPi6xFN5c63nAWiA1-_IdgYhDn04n0Onrf-yOWKT6aRoLw=="),
                Arguments.of("Chrome66", "N+7iUukwlDtmST91tjBmloAK0IJWhLb06FE3wDLqDgM=", "N+7iUukwlDtmST91tjBmloAK0IJWhLb06FE3wDLqDgM=", "iR-BO7qw9vzqewph824bmlcZydOfHKPLNKHQbwyJ6Tj3oXlFOWQN3XIIV7Ry7BtrvROWskmbMyhkEf_sRjC4i0wR1htgkEYn6xIBNImYilI=")
        );
    }

}
