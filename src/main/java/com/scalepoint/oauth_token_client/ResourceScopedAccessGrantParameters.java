package com.scalepoint.oauth_token_client;

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
     * @param resource Specific resource identifier
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
     * Gets the OAuth2 scope for the access request.
     *
     * @return OAuth2 scope
     */
    public String getScope() {
        return scope;
    }

    /**
     * Gets the specific resource identifier for the access request.
     *
     * @return Specific resource identifier
     */
    public String getResource() {
        return resource;
    }

    /**
     * Gets the resource tenant identifier.
     *
     * @return Resource tenant identifier
     */
    public String getTenantId() {
        return tenantId;
    }

    /**
     * Gets the original authentication method references.
     *
     * @return Original authentication method references
     */
    @SuppressWarnings("unused")
    public String[] getAmr() {
        return amr;
    }

    /**
     * Gets the authentication method references as a space-separated string.
     *
     * @return AMR values as a space-separated string, or null if no AMR values are set
     */
    protected String getAmrString() {
        return (amr == null || amr.length < 1)
                ? null
                : StringUtil.join(amr, " ");
    }
}
