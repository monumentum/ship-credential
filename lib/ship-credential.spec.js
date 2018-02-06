const ShipCredential = require('./ship-credential');
const { cloneDeep, noop } = require('lodash');

jest.useFakeTimers();

describe('Ship Credential', function () {
    const aMinute = 60; // in secs
    const roleOne = 'foo';
    const roleTwo = 'bar';
    const fakeModel = { id: 123, name: 'Guilherme', age: 23, roles: [roleOne] }
    const overrideSecret = 'OVERRIDESECRET';
    const overrideExpires = aMinute * 2;

    const accessTokenConfig = {
        secret: 'somesecret',
        fromModel: ['name'],
        config: {
            expiresIn: aMinute
        }
    };

    const rolesConfig = {
        types: [ roleOne, roleTwo ],
        modelProp: 'roles'
    };

    it('should throw error to instance ShipCredential without required params', () => {
        const throwRolesModelProp = () => new ShipCredential({roles: { types: ['x'] }, accessToken: { secret: 'some' }});
        const throwRolesTypes = () => new ShipCredential({roles: { modelProp: 'x' }, accessToken: { secret: 'some' }});
        const throwAccessToken = () => new ShipCredential({roles: { modelProp: 'x', types: ['x'] }});

        expect(throwRolesModelProp).toThrow();
        expect(throwRolesTypes).toThrow();
        expect(throwAccessToken).toThrow();
    });

    it('should inject roles into function', () => {
        const role = 'test';
        const ship = new ShipCredential(cloneDeep({
            accessToken: accessTokenConfig,
            roles: rolesConfig,
        }));

        const middlewareFake = roles => expect(roles);
        const wrap = ship.middlewareWrap(middlewareFake)(role);

        wrap().toBe(role);
        wrap().not.toBe('x');
    });

    baseAccessTokenValidation('without refresh token', {
        accessToken: accessTokenConfig,
        roles: rolesConfig,
    })

    baseAccessTokenValidation('with refresh token without override', {
        accessToken: accessTokenConfig,
        roles: rolesConfig,
        refreshToken: {
            modelId: 'id',
            config: {
                tolerance: aMinute
            }
        }
    }, (ship, opts, tokens) => {
        baseRefreshTokenValidation(ship, opts, tokens);

        it('should dont openDoor to refreshTokens', () => {
            expect(ship.openDoor(tokens.refreshToken, [ roleOne ])).toBe(false);
            expect(ship.openDoor(tokens.refreshToken, [ roleTwo ])).toBe(false);
        });
    });

    baseAccessTokenValidation('with refresh token with override data', {
        accessToken: accessTokenConfig,
        roles: rolesConfig,
        refreshToken: {
            secret: overrideSecret,
            modelId: 'id',
            config: {
                expiresIn: overrideExpires,
                tolerance: aMinute
            }
        }
    }, (ship, opts, tokens) => {
        it('should ship has the overrided configs', () => {
            expect(ship.opts.refreshToken.secret).toBe(overrideSecret);
            expect(ship.opts.refreshToken.config.expiresIn).toBe(
                overrideExpires + opts.refreshToken.config.tolerance
            );
        });

        it('should throw an exception when try to unpack refresh with access secret', () => {
            const throwWrongSecret = () => ship.openDoor(tokens.refreshToken, [ roleOne ]);
            expect(throwWrongSecret).toThrow();
        });

        baseRefreshTokenValidation(ship, opts, tokens);
    });

    function baseRefreshTokenValidation(ship, opts, tokens) {
        let refreshExpires = opts.refreshToken.config.expiresIn || opts.accessToken.config.expiresIn;
        refreshExpires = refreshExpires + opts.refreshToken.config.tolerance;

        it('should back refreshToken', () => {
            expect(tokens).toHaveProperty('refreshToken');
            expect(tokens).toHaveProperty('refreshTokenExpiresIn', refreshExpires);
        });

        it('should retrieveToken correctly for refreshToken', () => {
            const refreshData = ship.retrieveRefreshToken(tokens.refreshToken);
            expect(refreshData).toHaveProperty('data', { id: fakeModel.id });
        });
    }

    function baseAccessTokenValidation(switchName, opts, otherSwitchs = noop) {
        describe(switchName, () => {
            const ship = new ShipCredential(cloneDeep(opts));
            const tokens = ship.auth(fakeModel);

            it('should back accessToken', () => {
                expect(tokens).toHaveProperty('accessToken');
                expect(tokens).toHaveProperty('accessTokenExpiresIn', aMinute);
            });

            it('should retrieveToken correctly', () => {
                const accessData = ship.retrieveAccessToken(tokens.accessToken);
                expect(accessData).toHaveProperty('data', { name: fakeModel.name });
            });

            it('should exec openDoor correctly', () => {
                expect(ship.openDoor(tokens.accessToken, [ roleOne ])).toBe(true);
                expect(ship.openDoor(tokens.accessToken, [ roleTwo ])).toBe(false);
            });

            otherSwitchs(ship, opts, tokens);
        });
    }
});