package fish.payara.microprofile.jwtauth.eesecurity;

import static org.eclipse.microprofile.jwt.config.Names.ISSUER;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import com.nimbusds.jwt.SignedJWT;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;

/**
 *
 * @author XLKAFR
 */
public class SignedJWTIdentityStoreMutliIssuers extends SignedJWTIdentityStore {

    private static final Logger LOGGER = Logger.getLogger(SignedJWTIdentityStoreMutliIssuers.class.getName());

    protected List<String> acceptedIssuers;
    protected Map<String, JwtPublicKeyStore> issuer2PublicKeyStore;

    public SignedJWTIdentityStoreMutliIssuers() {

        Config config = ConfigProvider.getConfig();
        issuer2PublicKeyStore = new HashMap<>();

        Optional<List<String>> optionalIssuers = config.getOptionalValues(ISSUER + "s", String.class);
        if (optionalIssuers.isPresent()) {
            acceptedIssuers = optionalIssuers.get();
        } else {
            acceptedIssuers = Collections.emptyList();
        }

        for (String issuer : acceptedIssuers) {
            Optional<Properties> properties = readVendorProperties();
            String jwksUri = getJwksUri(issuer);
            if (jwksUri != null) {
                var ks = new JwtPublicKeyStore(readPublicKeyCacheTTL(properties), Optional.of(jwksUri));
                issuer2PublicKeyStore.put(issuer, ks);
            }
        }
    }

    @Override
    public int priority() {
        return super.priority() - 4;
    }

    public CredentialValidationResult validate(SignedJWTCredential signedJWTCredential) {
        if (!acceptedIssuers.isEmpty()) {
            try {
                SignedJWT jwt = SignedJWT.parse(signedJWTCredential.getSignedJWT());
                String issuer = jwt.getJWTClaimsSet().getIssuer();
                if (!acceptedIssuers.contains(issuer)) {
                    return CredentialValidationResult.NOT_VALIDATED_RESULT;
                }

                setAcceptedIssuer(issuer);
                setPublicKeyStore(issuer2PublicKeyStore.get(issuer));
            } catch (ParseException ex) {
                LOGGER.log(Level.SEVERE, null, ex);
            }
        }
        return super.validate(signedJWTCredential);
    }

    private static String getJwksUri(String issuer) {
        String jwksUri = null;
        try {
            URI issuerURI = new URI(issuer);
            String pathConfig = "";
            if (!issuerURI.getPath().endsWith("/")) {
                pathConfig += "/";
            }
            pathConfig += ".well-known/openid-configuration";
            URI providerConfigurationURI = issuerURI.resolve(issuerURI.getPath() + pathConfig);

            HttpRequest request = HttpRequest.newBuilder(providerConfigurationURI).GET().build();
            HttpClient client = HttpClient
                    .newBuilder()
                    .sslContext(NoOpSSLContextBuilder.build())
                    .build();
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() == 200) {
                try (InputStream inputStream = response.body(); JsonReader reader = Json.createReader(inputStream)) {
                    JsonObject config = reader.readObject();
                    if (config.containsKey("jwks_uri")) {
                        jwksUri = config.getString("jwks_uri");
                    } else {
                        LOGGER.log(Level.SEVERE, "Property 'jwks_uri' not found in openid-configuration from Issuer: {0}", providerConfigurationURI.toString());
                    }
                };
            } else {
                LOGGER.log(Level.SEVERE, "Cannot load openid-configuration from Issuer: {0} status code: {1}", new Object[]{providerConfigurationURI.toString(), response.statusCode()});
            }
        } catch (URISyntaxException | IOException | InterruptedException ex) {
            LOGGER.log(Level.SEVERE, "Error loading public certificate from Issuer " + issuer, ex);
        }
        return jwksUri;
    }
}
