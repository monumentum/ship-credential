const ShipCredential = require('./ship-credential');

describe('Ship Credential', () => {
    let auth;

    const instaceAuth = opts => () => {
        auth = new ShipCredential(opts);
    }

    const checkPermission = (token, roles) =>
        expect(auth.checkTokenPermission(token, roles))

    it('should throw error to instance ShipCredential without required params', () => {
        const throwRoleProp = () => new ShipCredential({ allowedRoles: ['x'], secret: 'x' });
        const throwAllowedProp = () => new ShipCredential({ registerOpts: {roleProp: 'x' }, secret: 'x' });
        const throwSecret = () => new ShipCredential({ registerOpts: {roleProp: 'x' }, allowedRoles: ['x'] });

        expect(throwRoleProp).toThrow();
        expect(throwAllowedProp).toThrow();
        expect(throwSecret).toThrow();
    });

    describe('without expire', () => {
        const roleOne = 'foo';
        const roleTwo = 'bar';
        const opts = {
            allowedRoles: [ roleOne, roleTwo ],
            secret: 'somesecret',
            registerOpts: {
                roleProp: 'roles',
                fields: ['name']
            }
        }

        beforeEach(instaceAuth(opts));

        it('should work register and verify a token to single role', () => {
            const fakeModel = { name: 'Guilherme', age: 23, roles: [roleOne] }
            const token = auth.registerToken(fakeModel);

            checkPermission(token, [roleOne]).toBe(ShipCredential.IS_ALLOWED);
            checkPermission(token, [roleTwo]).toBe(ShipCredential.IS_NOT_ALLOWED);
        });

        it('should work register and verify a token to mutiple role', () => {
            const fakeModel = { name: 'Guilherme', age: 23, roles: [roleOne, roleTwo] }
            const token = auth.registerToken(fakeModel);

            checkPermission(token, [roleOne]).toBe(ShipCredential.IS_ALLOWED);
            checkPermission(token, [roleTwo]).toBe(ShipCredential.IS_ALLOWED);
            checkPermission(token, [roleOne, roleTwo]).toBe(ShipCredential.IS_ALLOWED);
        });
    });
});