const jwt = require('jsonwebtoken');
const { merge, pick, get, has } = require('lodash');

const checkRoles = (tokenRoles, expectedRoles) =>
    tokenRoles.some(role => ~expectedRoles.indexOf(role))

const checkOpts = opts => [
    'accessToken.secret', 'roles.types', 'roles.modelProp'
].filter(opt => !has(opts, opt));

class ShipCredential {
    constructor(opts) {
        if (checkOpts(opts).length > 0) {
            throw new Error('@todo abstract MissingParameter/Configuration: to alert about');
        }

        this.opts = opts;

        if (this._useRefreshToken()) {
            this._getRefreshTokenOpts();
        }
    }

    auth(model) {
        const tokens = {};

        if (this._useRefreshToken()) {
            tokens.refreshTokenExpiresIn = this.opts.refreshToken.config.expiresIn;
            tokens.refreshToken = this.generateToken(model, this.opts.refreshToken);
        }

        tokens.accessTokenExpiresIn = this.opts.accessToken.config.expiresIn;
        tokens.accessToken = this.generateToken(model, this.opts.accessToken, true);

        return tokens;
    }

    openDoor(token, allowedRoles) {
        return this.checkRolesForToken(token, allowedRoles);
    }

    checkRolesForToken(token, allowedRoles) {
        const tokenRoles = this.retrieveAccessToken(token).roles || [];
        if (!checkRoles(tokenRoles, allowedRoles)) {
            return false;
        }

        return true;
    }

    retrieveAccessToken(token) {
        return this.retrieveToken(token, this.opts.accessToken.secret);
    }

    retrieveRefreshToken(token) {
        return this.retrieveToken(token, this.opts.refreshToken.secret);
    }

    retrieveToken(token, secret) {
        return jwt.verify(token, secret);
    }

    generateToken(model, opts, addRoles) {
        const tokenData = {
            createdAt: new Date(),
            data: pick(model, opts.fromModel),
            meta: opts.meta,
        };

        if (addRoles) {
            tokenData.roles = get(model, this.opts.roles.modelProp);
        }

        return jwt.sign(tokenData, opts.secret, opts.config);
    }

    _useRefreshToken() {
        return has(this, 'opts.refreshToken');
    }

    _getRefreshTokenOpts() {
        this.opts.refreshToken = merge({}, this.opts.accessToken, this.opts.refreshToken);

        this.opts.refreshToken.fromModel = [this.opts.refreshToken.modelId];
        this.opts.refreshToken.config.expiresIn = this.opts.refreshToken.config.expiresIn + this.opts.refreshToken.config.tolerance;

        delete this.opts.refreshToken.modelId;
        delete this.opts.refreshToken.config.tolerance;
    }
}

module.exports = ShipCredential;