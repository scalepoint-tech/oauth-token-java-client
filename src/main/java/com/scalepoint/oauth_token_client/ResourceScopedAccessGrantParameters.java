package com.scalepoint.oauth_token_client;

import org.apache.commons.lang3.StringUtils;

/**
 * OAuth2 Token endpoint parameters for urn:scalepoint:params:oauth:grant-type:resource-scoped-access grant.
 */
@SuppressWarnings("WeakerAccess")
public class ResourceScopedAccessGrantParameters {
    private final String scope;
    private final String resource;
    private String tenantId;
    private String[] amr;

    /**
     * Creates new ResourceScopedAccessGrantParameters
     * @param scope OAuth2 scope
     * @param resource Spefific resource identifier
     */
    public ResourceScopedAccessGrantParameters(String scope, String resource) {
        this.scope = scope;
        this.resource = resource;
    }

    /**
     * Creates new ResourceScopedAccessGrantParameters
     * @param scope OAuth2 scope
     * @param resource Specific resource identifier
     * @param tenantId Resource tenant identifier
     * @param amr Original authentication method references
     */
    @SuppressWarnings("SameParameterValue")
    public ResourceScopedAccessGrantParameters(String scope, String resource, String tenantId, String[] amr) {
        this(scope, resource);
        this.tenantId = tenantId;
        this.amr = amr;
    }

    /**
     * @return OAuth2 scope
     */
    public String getScope() {
        return scope;
    }

    /**
     * @return Specific resource identifier
     */
    public String getResource() {
        return resource;
    }

    /**
     * @return Resource tenant identifier
     */
    public String getTenantId() {
        return tenantId;
    }

    /**
     * @return Original authentication method references
     */
    @SuppressWarnings("unused")
    public String[] getAmr() {
        return amr;
    }

    protected String getAmrString() {
        return (amr == null || amr.length < 1)
                ? null
                : StringUtils.join(amr, " ");
    }
}
