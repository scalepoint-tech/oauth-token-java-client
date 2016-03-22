package com.scalepoint.jwt_assertion_client;

import org.apache.http.client.HttpResponseException;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.socket.PortFactory;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import static org.mockserver.matchers.Times.exactly;
import static org.mockserver.model.HttpRequest.request;

@SuppressWarnings("unused")
public class JwtAssertionTokenClientTest {

    private ClientAndServer mockServer;
    private String tokenEndpointUri;

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

    @Test
    public void testSuccess() throws Exception {

        mockServer.when(
                request()
                        .withSecure(true)
                        .withMethod("POST")
                        .withPath("/oauth2/token"),
                exactly(1)
        )
                .callback(HttpCallback.callback().withCallbackClass(SuccessfulExpectationCallback.class.getName()));

        TokenClient tokenClient = new JwtAssertionTokenClient(tokenEndpointUri, "clientid", TestCertificateHelper.load());
        tokenClient.getToken("success");
    }

    @Test
    public void testSuccessFromCache() throws Exception {

        HttpRequest request = request()
                .withSecure(true)
                .withMethod("POST")
                .withPath("/oauth2/token");
        mockServer.when(
                request,
                exactly(1)
        )
                .callback(HttpCallback.callback().withCallbackClass(SuccessfulExpectationCallback.class.getName()));

        TokenClient tokenClient = new JwtAssertionTokenClient(tokenEndpointUri, "clientid", TestCertificateHelper.load());
        tokenClient.getToken("cache");
        tokenClient.getToken("cache");
        Assert.assertEquals(mockServer.retrieveRecordedRequests(request).length, 1);
    }

    @Test
    public void testValidRequest() throws Exception {

        mockServer.when(
                request()
                        .withSecure(true)
                        .withMethod("POST")
                        .withPath("/oauth2/token"),
                exactly(1)
        )
                .callback(HttpCallback.callback().withCallbackClass(ValidRequestExpectationCallback.class.getName()));

        TokenClient tokenClient = new JwtAssertionTokenClient(tokenEndpointUri, "clientid", TestCertificateHelper.load());
        tokenClient.getToken("scope1", "scope2");
    }

    @Test(expectedExceptions = HttpResponseException.class)
    public void testFailure() throws Exception {

        mockServer.when(
                request()
                        .withSecure(true)
                        .withMethod("POST")
                        .withPath("/oauth2/token"),
                exactly(1)
        )
                .callback(HttpCallback.callback().withCallbackClass(BadRequestCallback.class.getName()));

        TokenClient tokenClient = new JwtAssertionTokenClient(tokenEndpointUri, "clientid", TestCertificateHelper.load());
        tokenClient.getToken("badRequest");
    }

}
