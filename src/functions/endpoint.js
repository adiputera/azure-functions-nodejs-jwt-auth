const { app } = require('@azure/functions');
const jwt = require('jsonwebtoken');

app.http('endpoint', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        try {
            const bearerToken = request.headers.get('Authorization');
            if (bearerToken && bearerToken.startsWith('Bearer ')) {
                const token = bearerToken.split(' ')[1];
                if (token) {
                    const decoded = jwt.verify(token, `${process.env['jwt_secret_key']}`);
                    if (decoded.sub && `${process.env[decoded.sub]}`) {
                        return {
                            status: 200,
                            headers: {
                                'content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                message: 'You have access to this endpoint'
                            })
                        };
                    }
                }
            }
        } catch (error) {
            context.log(error);
        }
        return {
            status: 401,
            headers: {
                'content-Type': 'application/json'
            },
            body: JSON.stringify({
                error: 'Unauthorized'
            })
        };
    }
});
