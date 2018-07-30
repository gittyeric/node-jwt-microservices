// A generic, hard-coded service that implements the following interface:
// Eventually it'd be nice to actually select rotated secrets by expiration date,
// perhaps by integrating with Google KMS

/*
interface SecretProvider {
    getSecretByExpireDate(expDate): Promise<string>,
}
*/

const getSecretByExpireDate = (secret) => 
    ((date) => Promise.resolve(secret));

module.exports = (secret) => ({
    getSecretByExpireDate: getSecretByExpireDate(secret),
});
