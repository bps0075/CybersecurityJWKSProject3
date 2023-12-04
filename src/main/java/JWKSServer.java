// Brandon Sharp, CSCS 3550
// Project 3: Bulking the extended JWKS Server from the Restful JWKS Server
// Note: When using SQLite make sure to fix the issues in Project Structure if any
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
import java.time.Instant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.jose4j.jwk.PublicJsonWebKey;

// Project 3 (P3) imports
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;


public class JWKSServer {
    //private static final String SECRET_KEY = "your-secret-key"; // Secret key
    private static RsaJsonWebKey jwk = null;
    private static RsaJsonWebKey expiredJWK = null;
    private static Connection c = null; // Private variable for the P2 database connection
    private static Statement statement = null; // This will only be used for needed statements
    private static String GoodExpiry = ""; // Expiry

    private static String envKey = "NOT_MY_KEY"; //P3

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

            //P3 code below
            boolean isAuthenticated = AuthenticateUser(); // Example authentication logic
            CreateUsersTable(c); //P3
            CreateAuthLogsTable(c);//P3
            if (isAuthenticated) {
                // Log authentication details into the 'auth_logs' table
                LogAuthenticationDetails(h.getRemoteAddress().getHostString(), GetUserId(), c); // Pass necessary details
            }
            // Return appropriate response based on authentication status
            String response = isAuthenticated ? "Authentication successful!" : "Authentication failed!";
            h.sendResponseHeaders(isAuthenticated ? 200 : 401, response.getBytes().length);
            os = h.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
        private boolean AuthenticateUser() {
            // Implement your authentication logic
            // Return true if authentication is successful, otherwise false
            return true; // Example: Always returning true for demonstration purposes
        }

        private int GetUserId() {
            // Retrieve user ID after successful authentication
            // Return the user ID of the authenticated user
            return 123; // Example: Replace with the actual user ID
        }

        private void LogAuthenticationDetails(String requestIP, int userId, Connection c) {
            try {
                // Prepare and execute SQL query to insert authentication details into the 'auth_logs' table
                if (c != null) {
                    String insertQuery = "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)";
                    PreparedStatement preparedStatement = c.prepareStatement(insertQuery);
                    preparedStatement.setString(1, requestIP);
                    preparedStatement.setInt(2, userId);
                    preparedStatement.executeUpdate();
                    preparedStatement.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
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
                ResultSet resultSet = preparedStatement.executeQuery(selectQuery); // Executes the select statement

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

    //P3 classes and methods below
    public class AESEncryption{ //P3 class
        private static String EncryptAES(String privateKey, String secretKey) throws Exception {
            //AES encryption of private keys
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = cipher.doFinal(privateKey.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }
        private static String DecryptAES(String encryptedPrivateKey, String secretKey) throws Exception {
            //AES decryption of private keys
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPrivateKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }
    }

    private static void CreateUsersTable(Connection c) {
        //Creates a users table in the database with appropriate fields to store information and hashed passwords
        if (c != null) { //If connection variable is not null
            try {
                Statement statement = c.createStatement();
                String createTableQuery = "CREATE TABLE IF NOT EXISTS users(\n" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,\n" +
                    "username TEXT NOT NULL UNIQUE,\n" +
                    "password_hash TEXT NOT NULL,\n" +
                    "email TEXT UNIQUE,\n" +
                    "date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n" +
                    "last_login TIMESTAMP\n" +
                    ")";
                statement.executeUpdate(createTableQuery);
                statement.close();
                System.out.println("Users table created (if not exists).");
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
    private static void CreateAuthLogsTable(Connection c) {
        //This database table is created to log authentication requests with schema
        if (c != null) { //If connection variable is not null
            try {
                Statement statement = c.createStatement();
                String createLogsTable = "CREATE TABLE IF NOT EXISTS auth_logs(\n" +
                    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n" +
                    "    request_ip TEXT NOT NULL,\n" +
                    "    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n" +
                    "    user_id INTEGER,  \n" +
                    "    FOREIGN KEY(user_id) REFERENCES users(id)\n" +
                    ");";
                statement.executeUpdate(createLogsTable);
                statement.close();
                System.out.println("Auth logs table created (if not exists).");
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    public class RegisterHandler implements HttpHandler { //P3
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Implement the logic for user registration here
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                //Parses the request body
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "UTF-8");
                BufferedReader br = new BufferedReader(isr);
                StringBuilder requestBody = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    requestBody.append(line);
                }
                //Extracts user details (assuming JSON format)
                //Example JSON: {"username": "user123", "password": "pass123", "email": "user@example.com"}
                String userData = requestBody.toString();
                //Parses JSON and extract user details (JSON library like Gson or Jackson)

                //Performs input validation to check if required fields are present and valid
                if (userData != null) {
                    // Perform user registration into the database
                    boolean registrationSuccess = RegisterUserIntoDatabase(userData, c);
                    if (registrationSuccess) {
                        String response = "User registered successfully!";
                        exchange.sendResponseHeaders(200, response.getBytes().length);
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    } else {
                        exchange.sendResponseHeaders(500, -1); // Internal Server Error
                    }
                } else {
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                }
            }
//              catch (SQLException e) {
//                e.printStackTrace();
//                exchange.sendResponseHeaders(500, -1); // Internal Server Error
//                // Perform user registration into the database
//                // Return appropriate response
//                String response = "User registered successfully!";
//                exchange.sendResponseHeaders(200, response.getBytes().length);
//                OutputStream os = exchange.getResponseBody();
//                os.write(response.getBytes());
//                os.close();
            else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
        private boolean RegisterUserIntoDatabase(String userData, Connection c) {
            try {
                // Extracts user details from userData and perform necessary validations
                // Example: Use a JSON library like Gson or Jackson to parse JSON data

                // Prepare and execute SQL query to insert user details into the 'users' table
                if (c != null) {
                    String insertQuery = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)";
                    PreparedStatement preparedStatement = c.prepareStatement(insertQuery);
                    // Set parameters based on extracted user details
                    // Example: preparedStatement.setString(1, extractedUsername);
                    //           preparedStatement.setString(2, extractedPasswordHash);
                    //           preparedStatement.setString(3, extractedEmail);
                    // Execute the SQL query
                    int rowsAffected = preparedStatement.executeUpdate();
                    preparedStatement.close();
                    return rowsAffected > 0; //If registration successful, return true
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
            return false; //Registration failed
        }
    }

    private static void RegisterUser() { //not coding in
        //Registers the user and stores the user data

    }

    private static void AuthUser() { //not coding in
        //Authenticates the user and does log authentication

    }

    public class RateLimiter { //Extra credit
        private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();

        public boolean allowRequest(String ipAddress, int maxRequests, int windowInSeconds) {
            long currentTime = System.currentTimeMillis() / 1000;
            AtomicInteger counter = requestCounts.computeIfAbsent(ipAddress, k -> new AtomicInteger());

            synchronized (counter) {counter.getAndUpdate(value -> {
                    if (currentTime - value > windowInSeconds) {
                        return 1;
                    } else {
                        return value + 1;
                    }});
                if (counter.get() > maxRequests) {
                    return false;
                }
            }
            return true;
        }
    }
}
