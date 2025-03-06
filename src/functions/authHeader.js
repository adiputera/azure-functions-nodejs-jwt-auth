const { app } = require('@azure/functions');
const jwt = require('jsonwebtoken');

app.http('authHeader', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'auth-header',
    handler: async (request, context) => {
        try {
            const authorization = request.headers.get('Authorization');
            if (authorization && authorization.startsWith('Basic ')) {
                const base64Credentials = authorization.split(' ')[1];
                const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
                const [clientId, clientSecret] = credentials.split(':');
                if (clientId && clientSecret) {
                    const savedClientSecret = `${process.env[clientId]}`;
                    const jwtSecretKey = `${process.env['jwt_secret_key']}`;
                    const jwtExpiresIn = parseInt(`${process.env['jwt_expire_time']}`);
                    if (savedClientSecret
                            && savedClientSecret === clientSecret
                            && jwtSecretKey
                            && jwtExpiresIn) {
                        const token = jwt.sign({
                            iss: 'adiputera',
                            sub: clientId
                        }, jwtSecretKey, {
                            expiresIn: jwtExpiresIn
                        });
                        return {
                            status: 200,
                            headers: {
                                'content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                'access_token': token,
                                'token_type': 'Bearer',
                                'expiresIn': jwtExpiresIn - 10
                            })
                        };
                    }
                }
            }
        } catch (error) {
            context.log(error);
        }
        return {
            status: 400,
            headers: {
                'content-Type': 'application/json'
            },
            body: JSON.stringify({
                error: 'Invalid credential'
            })
        };
    }
});
