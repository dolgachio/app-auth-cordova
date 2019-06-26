var exec = require('cordova/exec');

exports.authorize = function (
    issuer,
    redirectUrl,
    clientId,
    clientSecret,
    scopes,
    additionalParameters,
    serviceConfiguration,
    useNonce,
    usePKCE,
    resolve,
    reject) {

    exec(resolve, reject, 'AppAuthCordova', 'authorize', [
        issuer,
        redirectUrl,
        clientId,
        clientSecret,
        scopes,
        additionalParameters,
        serviceConfiguration,
        useNonce,
        usePKCE
    ]);
};
