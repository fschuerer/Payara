package fish.payara.microprofile.jwtauth.eesecurity;

import com.nimbusds.jwt.SignedJWT;
import static fish.payara.microprofile.jwtauth.eesecurity.SignedJWTIdentityStore.readVendorProperties;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
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
import static org.eclipse.microprofile.jwt.config.Names.ISSUER;

/**
 *
 * @author XLKAFR
 */
public class SignedJWTIdentityStoreMutliIssuers extends SignedJWTIdentityStore {

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
            var ks = new JwtPublicKeyStore(readPublicKeyCacheTTL(properties), Optional.of(issuer + "/certs"));
            issuer2PublicKeyStore.put(issuer, ks);
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
                Logger.getLogger(SignedJWTIdentityStoreMutliIssuers.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return super.validate(signedJWTCredential);
    }
}
