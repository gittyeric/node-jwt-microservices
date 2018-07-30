var JWT = require('jsonwebtoken');

const jwtOptions = {
    algorithm: 'RS256',  // HMAC using default SHA-256 hash algorithm
};

const getSecretByDecodedJWT = (secretProvider) => (jwt) => {
    const expirationDate = new Date(jwt.exp * 1000);
    console.log(secretProvider);
    return secretProvider.getSecretByExpireDate(expirationDate);
};

const getSecretByEncodedJWT = (secretProvider) => (jwtStr) => {
    const untrustedJWT = JWT.decode(jwtStr);
    if (untrustedJWT) {
        return getSecretByDecodedJWT(secretProvider)(untrustedJWT);
    }
    return Promise.reject(new Error('Invalid token'));
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

const decodeValidJWT = (secretProvider) => (jwtStr) => 
    new Promise((resolve, reject) => {
        getSecretByEncodedJWT(secretProvider)(jwtStr)
            .then((secret) => {
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

const encodeJWT = (secretProvider) => (rawJwt) =>
    new Promise((resolve, reject) => {
        getSecretByDecodedJWT(secretProvider)(rawJwt)
            .then((secret) => {
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

module.exports = (secretProvider) => {
    const decoder = decodeValidJWT(secretProvider);
    const encoder = encodeJWT(secretProvider);
    const secretFromDecoded = getSecretByDecodedJWT(secretProvider);
    const secretFromEncoded = getSecretByEncodedJWT(secretProvider);

    return {
        createJWT,
        decodeValidJWT: (encodedJWT) => decoder(encodedJWT),
        encodeJWT: (decodedJWT) => encoder(decodedJWT),
        getSecretByDecodedJWT: (decodedJWT) => secretFromDecoded(decodedJWT),
        getSecretByEncodedJWT: (encodedJWT) => secretFromEncoded(encodedJWT),
    };
};
