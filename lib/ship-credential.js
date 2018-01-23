const jwt = require('jsonwebtoken');
const { pick, get, has } = require('lodash');

const checkRoles = (tokenRoles, expectedRoles) =>
    tokenRoles.some(role => ~expectedRoles.indexOf(role))

const checkOpts = opts => [
    'secret', 'allowedRoles', 'registerOpts.roleProp'
].filter(opt => !has(opts, opt));

class ShipCredential {
    constructor(opts) {
        const constructorErrs = checkOpts(opts);

        if (constructorErrs.length > 0) {
            throw new Error('@todo abstract MissingParameter/Configuration: to alert about', constructorErrs);
        }

        this._shipRoles = opts.allowedRoles;
        this._secret = opts.secret;
        this._registerOpts = opts.registerOpts;
    }

    registerToken(model) {
        const tokenData = {
            createdAt: new Date(),
            roles: get(model, this._registerOpts.roleProp),
            meta: pick(model, this._registerOpts.fields)
        };

        return jwt.sign(tokenData, this._secret);
    }

    checkTokenPermission(token, roles) {
        const tokenData = jwt.decode(token, this._secret);

        if (!checkRoles(tokenData.roles, roles)) {
            return ShipCredential.IS_NOT_ALLOWED;
        }

        return ShipCredential.IS_ALLOWED;
    }
}

ShipCredential.IS_NOT_ALLOWED = 'IS_NOT_ALLOWED';
ShipCredential.IS_ALLOWED = 'IS_ALLOWED';

module.exports = ShipCredential;