package com.scalepoint.oauth_token_client;

import org.apache.http.client.HttpResponseException;
import org.mockserver.model.HttpCallback;
import org.mockserver.model.HttpRequest;
import org.testng.Assert;
import org.testng.annotations.Test;

import static org.mockserver.matchers.Times.exactly;
import static org.mockserver.model.HttpRequest.request;

@SuppressWarnings("unused")
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
                .callback(HttpCallback.callback().withCallbackClass(SuccessfulExpectationCallback.class.getName()));

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
                .callback(HttpCallback.callback().withCallbackClass(SuccessfulExpectationCallback.class.getName()));

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
                .callback(HttpCallback.callback().withCallbackClass(ValidClientAssertionExpectationCallback.class.getName()));

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
                .callback(HttpCallback.callback().withCallbackClass(SuccessfulExpectationCallback.class.getName()));

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
