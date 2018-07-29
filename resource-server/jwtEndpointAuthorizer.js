
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
    }

    _addIdentityToReq(req, requiredRoles) {
        return getSecretByExpireDate(req).then((secret) => {
            readJwt(req, secret)
                .then((jwt) => {
                    const permError = requiredRoles.find((roleName) => {
                        const roleFilters = filters[roleName];
                        const roleValue = jwt.permissions[roleName];
                        const error = roleValue === undefined ||
                            roleFilters.find((filter) => !filter(roleName, roleValue));
                        if (error) {
                            console.log(`Identity ${jwt.userId} is missing valid value for role ${roleName}: ${roleValue}`);
                            res.sendStatus(403);
                            res.send('Not authorized');
                            return true;
                        }
                    });
                    return permError;
                })
                .then((permError) => {
                    if (!permError) {
                        req.user = jwt;
                        next();
                    }
                    throw new Error('Missing Permission');
                })
                .catch((e) => {
                    console.log('Failed authentication, invalid token. ' + e);
                    res.sendStatus(401);
                });
        })
            .catch((e) => {
                if (!e.status) {
                    e.status = 500;
                    e.publicMessage = 'Error Encountered';
                    console.log(e);
                }
                throw e;
            });
    }

    // EndpointAuthorizers are only open to authenticated users by default.
    // Use this to open endpoints to the entire world
    openToPublic() {
        this.isPublic = true;
        return this.secure();
    }

    // Require roleName to exist in token.
    // The roleValueFilter should return true if the
    // passed in (roleName, roleValue) meets criteria
    evaluateRole(roleName, roleValueFilter) {
        if (!this.filters[roleName]) {
            this.filters[roleName] = [];
        }
        this.filters[roleName].push(roleValueFilter);
    }

    hasRole(roleName) {
        this.evaluateRole(roleName, roleExistsFilter);
    }

    roleEquals(roleName, roleValue) {
        this.evaluateRole(roleName, roleEqualsFilter(roleValue));
    }

    // Build the middleware and secure JWT tokens using a secretProvider
    secure() {
        const requiredRoles = Object.keys(this.filters);
        const _this = this;

        // Sanity check for noobs or the lazy
        if (requiredRoles.length === 0) {
            throw new Error(
                'Cannot build endpointAuthorizer that is private' +
                ' but has no roles, call openToPublic for now if prototyping' +
                ' so it\'s marked explicitly!');
        }

        return (req, res, next) => {
            // TODO
            _this._addIdentityToReq(req, requiredRoles)
                .then((jwt) => {
                    next();
                })
                .catch((e) => {
                    res.sendStatus(e.status);
                    res.send(e.publicMessage);
                });
        }
    }
};

module.exports = (secretProvider) => {
    const builder = () => new EndpointAuthorizerBuilder(secretProvider);
    return {
        openToPublic: () => builder().openToPublic(),
        hasRole: (roleName) => builder().hasRole(roleName),
        roleEquals: (roleName, roleVal) => builder().roleEquals(roleName, roleVal),
        evaluateRole: (roleName, roleValFilter) => builder().evaluateRole(roleName, roleValFilter),
    };
};
