// HTTP-layer helpers
const BEARER_HEADER = 'Bearer: '
const skipBearerLen = BEARER_HEADER.length;

const readBearerToken = (req) => {
    const headerVal = req.headers['authentication'] || BEARER_HEADER;
    return headerVal.substring(skipBearerLen);
};

const readJwt = (req, secret) => {
    const bearer = readBearerToken(req);
    return decryptJWT(bearer, secret);
}

// TODO: Probably need to serialize jwt.exp to proper Date obj
const getSecretForJWT = (jwt) =>
    getSecretByExpireDate(secret)(new Date(jwt.exp * 1000));

const getExpireDateFromReq = (req) => {
    const decodedJWT = JWT.decode(get);
    return new Date(decodedJWT.exp * 1000);
}

module.exports = {
    getExpireDateFromReq,
};
