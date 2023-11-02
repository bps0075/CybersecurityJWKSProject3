// Brandon Sharp, CSCS 3550
// Project 2: Extending the JWKS Server from the basic Restful JWKS Server
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

// Project 2 (P2) imports
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.DatabaseMetaData;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.security.PublicKey;
import java.time.LocalTime;

// Extras
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.time.Instant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.jose4j.jwk.PublicJsonWebKey;

public class JWKSServer {
    //private static final String SECRET_KEY = "your-secret-key"; // Secret key
    private static RsaJsonWebKey jwk = null;
    private static RsaJsonWebKey expiredJWK = null;
    private static Connection c = null; // Private variable for the P2 database connection
    private static Statement statement = null; // This will only be used for needed statements
    private static String GoodExpiry = ""; // Expiry

    public static void main(String[] args) throws Exception {
        // Generates an RSA key pair, which will be used for signing and verification of the JWT and wrapped in a JWK
        GoodExpiry = Integer.toString((int) ((System.currentTimeMillis() / 1000) + 3600));
        jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId("goodKey1");
        expiredJWK = RsaJwkGenerator.generateJwk(2048);
        expiredJWK.setKeyId("expiredKey");

        // Below initializes the database connection for Project 2
        //String url = "jdbc:sqlite:totally_not_my_privateKeys.db";
        //c = DriverManager.getConnection("jdbc:sqlite:totally_not_my_privateKeys.db"); // Sets up the db connection
        //statement = c.createStatement(); // Creates the statement
        //statement.setQueryTimeout(30);  // sets timeout to 30 sec
        try {
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:totally_not_my_privateKeys.db"); // Sets up the db connection
            //c = DriverManager.getConnection(url);
            statement = c.createStatement(); // Creates the statement
            //statement.setQueryTimeout(30);  // sets timeout to 30 sec
            statement.execute("CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)");
            System.out.println("Database connection created!");
        } catch (ClassNotFoundException | SQLException e) {
            e.printStackTrace();
            System.err.println("Failed to connect to the database.");
            return; // Exits
        }

        // This part is the first step to creating and authenticating the server
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler()); // Handles that website link
        server.createContext("/auth", new AuthHandler()); // Creates the authenticator
        server.setExecutor(null); // Creates a default executor
        server.start();
        System.out.println("Server is running on port 8080....."); // Testing the server
    }

    static class JWKSHandler implements HttpHandler {
        // This function below handles http request GET and storing the key pair
        @Override
        public void handle(HttpExchange h) throws IOException {
            if (!"GET".equalsIgnoreCase(h.getRequestMethod())) {
                h.sendResponseHeaders(405, -1); // 405 means Method Not Allowed
                return;
            }
            // P2: Generates a new key pair
            //RsaJsonWebKey newKeyPair = RsaJwkGenerator.generateJwk(2048);
            //newKeyPair.setKeyId("newKey1");

            // P2: Stores the new key pair in the database
            StoreKeyPairInDatabase(jwk);
            System.out.println("Got past the storing part"); // Testing
            // P2: Generates a JSON Web Key Set (JWKS) response
            //JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(newKeyPair);
            //String jwks = jsonWebKeySet.toJson();

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwk); // Generates a Json web key set
            String jwks = jsonWebKeySet.toJson();
            h.getResponseHeaders().add("Content-Type", "application/json");
            h.sendResponseHeaders(200, jwks.length());
            OutputStream os = h.getResponseBody();
            os.write(jwks.getBytes());
            os.close();
        }
    }

    static class AuthHandler implements HttpHandler {
        // This function below handles the http request POST and getting the key pair
        @Override
        public void handle(HttpExchange h) throws IOException {
            if (!"POST".equalsIgnoreCase(h.getRequestMethod())) {
                h.sendResponseHeaders(405, -1); // 405 means Method Not Allowed
                return;
            }
            // P2: Gets the key pair from the database
            String keyId = "newKey1"; // Replace with the appropriate key ID
            RsaJsonWebKey keyPair = GetKeyPairFromDatabase(keyId);
            //PublicJsonWebKey keyPair = GetKeyPairFromDatabase(keyId);

            // P2: Checks if the key pair is null
            /*if (keyPair == null) {
                // Handles the case when the key pair is not found in the database
                h.sendResponseHeaders(404, -1); // 404 means Not Found
                OutputStream os = h.getResponseBody();
                os.write("Key pair not found".getBytes());
                os.close();
            }*/

            // Creates the claims JWT claims and signs the token
            JwtClaims claims = new JwtClaims();
            claims.setGeneratedJwtId(); // Sets it up with an id
            claims.setIssuedAtToNow(); // Gets issued
            claims.setSubject("sampleUser"); // Sets the user
            claims.setExpirationTimeMinutesInTheFuture(10); // Sets up JWT with expiry

            JsonWebSignature jws = new JsonWebSignature();
            jws.setKeyIdHeaderValue(jwk.getKeyId());
            jws.setKey(jwk.getPrivateKey()); // Sets the key as private

            // Checks for the expired query parameter
            if (h.getRequestURI().getQuery() != null && h.getRequestURI().getQuery().contains("expired=true")) {
                NumericDate expirationTime = NumericDate.now();
                expirationTime.addSeconds(-10 * 60); // Subtracts 10 minutes
                claims.setExpirationTime(expirationTime);
                jws.setKeyIdHeaderValue(expiredJWK.getKeyId());
                jws.setKey(expiredJWK.getPrivateKey()); // Sets this expiry as private
            }

            jws.setPayload(claims.toJson()); // Sets the payload
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256); //RSA_USING_SHA256 works

            String jwt = ""; // Start with a blank string
            try {
                jwt = jws.getCompactSerialization(); // Tries to get it
            } catch (JoseException e) {
                e.printStackTrace();
                h.sendResponseHeaders(500, -1); // 500 means Internal Server Error
                return;
            }

            h.sendResponseHeaders(200, jwt.length()); // 200 means OK
            OutputStream os = h.getResponseBody();
            os.write(jwt.getBytes());
            os.close(); // Closes the output stream so that it does not get in the way
        }
    }

    private static void StoreKeyPairInDatabase(RsaJsonWebKey keyPair) {
        // P2 function: This function stores the key pair into the SQLite database
        if (c != null) {
            try {
                String insertQuery = "INSERT INTO keys (key, exp) VALUES (?, ?)"; // Insert query
                PreparedStatement preparedStatement = c.prepareStatement(insertQuery);
                preparedStatement.setString(1, keyPair.toJson());
                preparedStatement.setString(2, GoodExpiry.toString()); // GoodExpiry is used as string
                preparedStatement.executeUpdate(); // Executes the insert into the database
                preparedStatement.close();
                System.out.println("KeyPair variable is: " + keyPair); // Testing
                System.out.println("Key pair stored in the database.");
            } catch (SQLException e) {
                e.printStackTrace();
                System.err.println("Failed to store the key pair in the database.");
            }
        }
    }

    private static RsaJsonWebKey GetKeyPairFromDatabase(String keyId) {
        // P2 function: This function gets the key pair from the SQLite database
        if (c != null) {
            try {
                //String selectQuery = "SELECT key FROM keys WHERE exp >= ?"; // Select query
                //String selectQuery = "SELECT key FROM keys WHERE key = ?";
                String selectQuery = "SELECT key FROM keys WHERE kid = ?";
                PreparedStatement preparedStatement = c.prepareStatement(selectQuery); // Prepares for the statement to be executed
                String x = Integer.toString((int) (System.currentTimeMillis() / 1000)); // x is the time as a string
                preparedStatement.setString(1, x);
                ResultSet resultSet = preparedStatement.executeQuery(); // Executes the select statement

                if (resultSet.next()) {
                    String keyJson = resultSet.getString("key");
                    //return (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(keyJson);
                    return (RsaJsonWebKey) RsaJsonWebKey.Factory.newPublicJwk(keyJson); // RSA may not work
                }
                preparedStatement.close();
            } catch (SQLException | JoseException e) {
                e.printStackTrace();
                System.err.println("Failed to retrieve the key pair from the database.");
            }
        }
        return null;
    }
}
