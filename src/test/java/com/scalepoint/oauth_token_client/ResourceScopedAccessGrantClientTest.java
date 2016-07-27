package com.scalepoint.oauth_token_client;

import org.mockserver.model.HttpCallback;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.mockserver.matchers.Times.exactly;
import static org.mockserver.model.HttpRequest.request;

@SuppressWarnings("unused")
public class ResourceScopedAccessGrantClientTest extends MockServerTestBase {

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

        ResourceScopedAccessGrantTokenClient tokenClient = new ResourceScopedAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
        tokenClient.getToken(new ResourceScopedAccessGrantParameters("scope", "resource"));
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
                .callback(HttpCallback.callback().withCallbackClass(ValidResourceScopedAccessRequestCallback.class.getName()));

        ResourceScopedAccessGrantTokenClient tokenClient = new ResourceScopedAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
        tokenClient.getToken(new ResourceScopedAccessGrantParameters("scope", "resource", "tenantId", new String[] {"pwd", "otp", "mfa"}));
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
                .callback(HttpCallback.callback().withCallbackClass(BadRequestCallback.class.getName()));

        ResourceScopedAccessGrantTokenClient tokenClient = new ResourceScopedAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
        tokenClient.getToken(new ResourceScopedAccessGrantParameters("scope", "resource"));
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

        ResourceScopedAccessGrantTokenClient tokenClient = new ResourceScopedAccessGrantTokenClient(
                tokenEndpointUri,
                new JwtBearerClientAssertionCredentials(
                        tokenEndpointUri,
                        "clientid",
                        TestCertificateHelper.load()
                )
        );
        tokenClient.getToken(new ResourceScopedAccessGrantParameters("scope", "resource"));
    }

}
