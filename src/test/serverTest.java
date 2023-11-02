import org.junit.Test;
import static org.junit.Assert.*;
import org.evosuite.runtime.EvoRunner;
import org.evosuite.runtime.EvoRunnerParameters;
import org.junit.runner.RunWith;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@RunWith(EvoRunner.class) @EvoRunnerParameters(mockJVMNonDeterminism = true, useVFS = true, useVNET = true, resetStaticState = true, separateClassLoader = true, useJEE = true)
public class serverTest { //This will test the JWKSServer.java file by calling the functions to produce code coverage
    @Test
    public void testJWKSServerInitialization() {
        JWKSServer server = new JWKSServer();
        assertNotNull(server, "JWKSServer should be initialized"); // Asserts that the JWKSServer instance is not null
        assertNotNull(server.jwk, "Key pair should be initialized"); // Asserts that the key pair is not null
        assertNotNull(server.c, "Database connection should be established"); // Asserts that the database connection is not null
    }
    @Test // used for testing
    public void testJWKSHandler() {
        // Test cases to test the JWKSHandler functionality are below
        // Uses assertions to check the expected results
        JWKSServer.JWKSHandler jwksHandler = new JWKSServer.JWKSHandler();
        JWKSServer server = new JWKSServer();
        assertNotNull(server.JWKSHandler()); //Checks if the JWKSHandler server works

        String jwksResponse = jwksHandler.generateJWKSResponse(server.jwk); // Generates a JWKS response
        assertNotNull(jwksResponse, "JWKS response should not be null"); // Asserts that the JWKS response is not null
        }
    }

    @Test
    public void testAuthHandler() {
        // Test cases to test the AuthHandler functionality are below
        // Uses assertions to check the expected results
        JWKSServer server = new JWKSServer();
        assertNotNull(server.AuthHandler()); //Checks that the AuthHandler works
    }
}