
// Role Filter helpers

const roleEqualsFilter = (requiredVal) =>
    (roleName, roleVal) => roleVal === requiredVal;

const roleNotEqualsFilter = (requiredVal) =>
    (roleName, roleVal) => roleVal !== requiredVal;

const roleExistsFilter = () =>
    roleNotEqualsFilter(undefined);

// Express middleware builder to customize permission requirements
class EndpointAuthorizerBuilder {
    constructor(secretProvider) {
        this.secretProvider = secretProvider;
        this.isPublic = false;
        this.filters = {};
        this.validClientIdIssuers = null; // Array of clientIds that could have issued the token
    }

    _validatePermissions(jwt, requiredRoles) {
        const filters = this.filters;
        return requiredRoles.find((roleName) => {
            const roleFilters = filters[roleName];
            const roleValue = jwt.permissions[roleName];
            const error = roleValue === undefined ||
                roleFilters.find((filter) => !filter(roleName, roleValue));
            if (error) {
                console.log(`Identity ${jwt.userId} is missing valid value for role ${roleName}: ${roleValue}`);
                return true;
            }
        }) ? new Error('Not Authorized') : false;
    }

    _validateIssuer(jwt) {
        return
            !this.validClientIdIssuers ||
            this.validClientIdIssuers.find(jwt.iss) ?
                false :
                new Error(`${jwt.iss} is not a valid Issuer`);
    }

    _validate(req, requiredRoles) {
        const _this = this;
        const isPublic = this.isPublic;
        return new Promise((resolve, reject) => {
            getSecretByReq(req).then((secret) => {
                return readJwt(req, secret)
                    .then((jwt) => {
                        const permError =
                            _this._validateIssuer(jwt) ||
                            _this._validatePermissions(jwt, requiredRoles);
                        if (permError) {
                            e.status = 403;
                            e.publicMessage = 'Not authorized';
                        }
                        if (permError) {
                            throw permError;
                        }
                        return jwt;
                    })
                    .catch((e) => {
                        console.log('Failed authentication, invalid token. ' + e);
                        if (!e.status) {
                            e.status = 401;
                            e.publicMessage = 'Error Encountered';
                        }
                        throw e;
                    });
            })
                .then((jwt) => {
                    resolve(jwt);
                })
                .catch((e) => {
                    // Allow the request anyway if endpoint is public
                    if (isPublic) {
                        resolve(null);
                    }
                    else {
                        if (!e.status) {
                            e.status = 500;
                            e.publicMessage = 'Error Encountered';
                            console.log(e);
                        }
                        reject(e);
                    }
                });
        });
    }

    // Resolves with valid JWT that's also written to req
    // or returns an authorization error
    _addIdentityToReq(req, validatePromise) {
        return validatePromise
            .then((jwt) => {
                req.identity = jwt;
                return jwt;
            });
    }

    // EndpointAuthorizers are only open to authenticated users by default.
    // Use this to open endpoints to the entire world
    openToPublic() {
        this.isPublic = true;
        return this.build();
    }

    allowClientIds(clientIdWhitelist) {
        // If not array
        if (clientIdWhitelist.length === undefined) {
            this.validClientIdIssuers = [clientIdWhitelist];
        }
        else {
            this.validClientIdIssuers = [...clientIdWhitelist];
        }
        return this;
    }

    // Require roleName to exist in token.
    // The roleValueFilter should return true if the
    // passed in (roleName, roleValue) meets criteria
    filterRole(roleName, roleValueFilter) {
        if (!this.filters[roleName]) {
            this.filters[roleName] = [];
        }
        this.filters[roleName].push(roleValueFilter);
        return this;
    }

    hasRole(roleName) {
        this.filterRole(roleName, roleExistsFilter);
        return this;
    }

    roleEquals(roleName, roleValue) {
        this.filterRole(roleName, roleEqualsFilter(roleValue));
        return this;
    }

    // Build the middleware and secure JWT tokens using a secretProvider
    build() {
        const requiredRoles = Object.keys(this.filters);
        
        // Sanity check for noobs or the lazy
        if (!this.isPublic) {
            if (requiredRoles.length === 0) {
                throw new Error(
                    'Cannot build endpointAuthorizer that is private' +
                    ' but has no roles, call openToPublic for now if prototyping' +
                    ' so it\'s marked explicitly!');
            }
            if (this.validClientIdIssuers.length === 0) {
                throw new Error(
                    'Cannot build endpointAuthorizer that is private' +
                    ' but has no valid clientIdIssuers. Either supply ' +
                    'some or do not call allowClientIds');
            }
        }

        const _this = this;
        return (req, res, next) => {
            const validating = _this._validate(req, requiredRoles)
            _this._addIdentityToReq(req, validating)
                .then(() =>
                    next())
                .catch((e) => {
                    res.send(e.publicMessage);
                    res.sendStatus(e.status);
                });
        };
    }
};

module.exports = (secretProvider) => {
    const builder = () => new EndpointAuthorizerBuilder(secretProvider);
    return {
        openToPublic: () => builder().openToPublic(),

        allowClientIds: (issuerWhitelist) => builder().allowClientIds(issuerWhitelist),

        hasRole: (roleName) => builder().hasRole(roleName),
        roleEquals: (roleName, roleVal) => builder().roleEquals(roleName, roleVal),
        filterRole: (roleName, roleValFilter) => builder().filterRole(roleName, roleValFilter),
    };
};
