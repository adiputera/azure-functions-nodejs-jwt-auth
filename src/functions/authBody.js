const { app } = require('@azure/functions');
const jwt = require('jsonwebtoken');
const querystring = require('querystring');

app.http('authBody', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'auth-body',
    handler: async (request, context) => {
        try {
            const body = await request.text();
            const parsedBody = querystring.parse(body);
            const clientId = parsedBody.client_id;
            const clientSecret = parsedBody.client_secret;
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
