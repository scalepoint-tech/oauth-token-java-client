package com.scalepoint.oauth_token_client;

import org.apache.http.client.HttpResponseException;
import org.mockserver.model.HttpCallback;
import org.testng.annotations.Test;

import static org.mockserver.matchers.Times.exactly;
import static org.mockserver.model.HttpRequest.request;

@SuppressWarnings("unused")
public class DelegateAccessGrantTest extends MockServerTestBase {

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

        TokenClient tokenClient = new DelegateAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                ),
                "resource",
                "amr"
        );
        tokenClient.getToken("success");
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
                .callback(HttpCallback.callback().withCallbackClass(ValidDelegationRequestCallback.class.getName()));

        TokenClient tokenClient = new DelegateAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                ),
                "resource",
                "amr"
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

        TokenClient tokenClient = new DelegateAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                ),
                "resource",
                "amr"
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

        TokenClient tokenClient = new DelegateAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                ),
                "resource",
                "amr"
        );
        tokenClient.getToken();
    }

}
