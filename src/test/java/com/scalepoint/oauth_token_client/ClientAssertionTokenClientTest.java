package com.scalepoint.oauth_token_client;

import org.mockserver.model.HttpClassCallback;
import org.mockserver.model.HttpRequest;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.mockserver.matchers.Times.exactly;
import static org.mockserver.model.HttpRequest.request;

public class ClientAssertionTokenClientTest extends MockServerTestBase {

    @Test
    public void testSuccess() throws Exception {

        mockServer.when(
                request()
                        .withSecure(true)
                        .withMethod("POST")
                        .withPath("/oauth2/token"),
                exactly(1)
        )
                .respond(HttpClassCallback.callback(SuccessfulExpectationCallback.class));

        ClientCredentialsGrantTokenClient tokenClient = new ClientCredentialsGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
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
                .respond(HttpClassCallback.callback(SuccessfulExpectationCallback.class));

        ClientCredentialsGrantTokenClient tokenClient = new ClientCredentialsGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
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
                .respond(HttpClassCallback.callback(ValidClientAssertionExpectationCallback.class));

        ClientCredentialsGrantTokenClient tokenClient = new ClientCredentialsGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
        tokenClient.getToken("scope1", "scope2");
    }

    @Test(expectedExceptions = IOException.class)
    public void testFailure() throws Exception {

        mockServer.when(
                request()
                        .withSecure(true)
                        .withMethod("POST")
                        .withPath("/oauth2/token"),
                exactly(1)
        )
                .respond(HttpClassCallback.callback(BadRequestCallback.class));

        ClientCredentialsGrantTokenClient tokenClient = new ClientCredentialsGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
        tokenClient.getToken("badRequest");
    }

    @Test
    public void testEmptyScopes() throws Exception {

        mockServer.when(
                request()
                        .withSecure(true)
                        .withMethod("POST")
                        .withPath("/oauth2/token"),
                exactly(1)
        )
                .respond(HttpClassCallback.callback(SuccessfulExpectationCallback.class));

        ClientCredentialsGrantTokenClient tokenClient = new ClientCredentialsGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
        tokenClient.getToken();
    }

}
