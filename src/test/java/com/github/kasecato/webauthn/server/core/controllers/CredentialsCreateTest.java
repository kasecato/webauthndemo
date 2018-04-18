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
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CredentialsCreateTest {

    @ParameterizedTest
    @MethodSource("jsonProvider")
    void create(
            final String browser,
            final String challengeGet,
            final String credentialId)
            throws Exception {

        final CredentialModel result = doCreate(browser, challengeGet);
        assertEquals(credentialId, result.getId());
        assertNotNull(result.getId());
    }

    public CredentialModel doCreate(
            final String browser,
            final String savedChallengeBase64Encoded)
            throws Exception {

        final String finishMakeCredJson = new ObjectMapper().readTree(
                new File(getClass().getClassLoader()
                        .getResource(String.format("FinishMakeCredentialTest_Request_%s.json", browser)).getFile())).toString();

        return CredentialsCreate.create(
                "localhost",
                finishMakeCredJson,
                savedChallengeBase64Encoded,
                Collections.emptySet());
    }

    static Stream<Arguments> jsonProvider() {
        return Stream.of(
                Arguments.of("Chrome65", "OkT8IA3R+yfLJmKMkQR8awmnHgwsT4p7LvPXwuDJiBk=", "wujRudeGT-b85GQO3oNNVWfnNe3SDK3_IvLLuhMIYPi6xFN5c63nAWiA1-_IdgYhDn04n0Onrf-yOWKT6aRoLw=="),
                Arguments.of("Chrome66", "N+7iUukwlDtmST91tjBmloAK0IJWhLb06FE3wDLqDgM=", "iR-BO7qw9vzqewph824bmlcZydOfHKPLNKHQbwyJ6Tj3oXlFOWQN3XIIV7Ry7BtrvROWskmbMyhkEf_sRjC4i0wR1htgkEYn6xIBNImYilI=")
        );
    }

}
