class RegistryBuilder {
    constructor() {
        this.state = {
            accessTokens: null, // Single provider only
            refreshTokens: null, // Single provider only
            secrets: null, // Single provider only
            identities: {}, // Map from name to IdentityProvider
            permissions: {}, // Map from name to PermissionsProvider
        };
    }

    setAccessTokenProvider(tokenProvider) {
        this.state.accessTokens = tokenProvider;
        return this;
    }

    setRefreshTokenProvider(refreshTokenProvider) {
        this.state.refreshTokens = refreshTokenProvider;
        return this;
    }

    setSecretProvider(secretProvider) {
        this.state.secrets = secretProvider;
        return this;
    }

    addIdentityProvider(name, identityProvider) {
        this.state.identities[name] = identityProvider;
        return this;
    }

    addPermissionsProvider(name, permissionsProvider) {
        this.state.permissions[name] = permissionsProvider;
        return this;
    }

    _build() {
        return { ...this.state };
    }
}

const registryBuilder = new RegistryBuilder();
module.exports = {
    builder: registryBuilder,
    registry: () => registryBuilder._build(),
};
