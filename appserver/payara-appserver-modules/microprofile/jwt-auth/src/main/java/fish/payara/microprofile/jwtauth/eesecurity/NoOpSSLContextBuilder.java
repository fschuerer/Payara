package fish.payara.microprofile.jwtauth.eesecurity;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

class NoOpSSLContextBuilder {

    static TrustManager[] noopTrustManager = new TrustManager[]{
        new X509TrustManager() {

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }
        }
    };

    static SSLContext build() {

        try {
            SSLContext sc = SSLContext.getInstance("ssl");
            sc.init(null, noopTrustManager, null);
            return sc;
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            Logger.getLogger(NoOpSSLContextBuilder.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
}
