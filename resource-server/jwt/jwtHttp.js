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

const getExpireDateFromReq = (req) => {
    const decodedJWT = JWT.decode(get);
    return new Date(decodedJWT.exp * 1000);
}

module.exports = {
    getExpireDateFromReq,
};
