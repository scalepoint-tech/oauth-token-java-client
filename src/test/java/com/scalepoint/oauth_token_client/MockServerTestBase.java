package com.scalepoint.oauth_token_client;

import org.mockserver.integration.ClientAndServer;
import org.mockserver.socket.PortFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class MockServerTestBase {
    ClientAndServer mockServer;
    String tokenEndpointUri;

    @BeforeClass
    public void disableCertificateValidation() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[]{new TrustAllX509TrustManager()}, new java.security.SecureRandom());
        SSLContext.setDefault(sc);
    }

    @BeforeClass
    public void start() {
        int port = PortFactory.findFreePort();
        tokenEndpointUri = "https://localhost:" + port + "/oauth2/token";
        mockServer = ClientAndServer.startClientAndServer(port);
    }

    @BeforeMethod
    public void reset() {
        mockServer.reset();
    }

    @AfterClass
    public void stop() {
        mockServer.stop();
    }
}
