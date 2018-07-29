var JWT = require('jsonwebtoken');

const jwtOptions = {
    algorithms: ['HS256']  // HMAC using SHA-256 hash algorithm
};

const createJWT = (identityId, expirationInSecs, jwtIssuer, permissions) => {
    var expireDate = new Date();
    expireDate.setSeconds(expireDate.getSeconds() + expirationInSecs);
    return {
        // public claims
        iss: jwtIssuer,
        exp: expireDate,

        // private claims
        userId: identityId,
        ...permissions,
    };
};

const decryptJWT = (secretProvider) => (jwtStr, expirationDate) => {
    return new Promise((resolve, reject) => {
        secretProvider.getSecretForExpireDate(expirationDate).then((secret) => {
            JWT.verify(jwtStr, secret, jwtOptions, (err, decoded) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(decoded);
                }
            });
        })
        .catch((e) => {
            reject(e);
        })
    });
};

const encryptJWT = (secretProvider) => (rawJwt) => {
    return new Promise((resolve, reject) => {
        secretProvider.getSecretForJWT(rawJwt).then((secret) => {
            JWT.sign(rawJwt, secret, jwtOptions, (err, encoded) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(encoded);
                }
            });
        })
        .catch((e) => {
            reject(e);
        })
    });
};

module.exports = (secretProvider) => ({
    createJWT,
    decryptJWT: decryptJWT(secretProvider),
    encryptJWT: encryptJWT(secretProvider),
});
