const passport = require('passport');
const jwt = require('jsonwebtoken');
const { Responder } = require('adapt-authoring-core');
const { MiddlewareModule } = require('adapt-authoring-middleware');
/**
 * Middleware for the auth module
 */
class Middleware extends MiddlewareModule {
    /**
     * Called before login attempt
     * @param {ClientRequest} req The client request object
     * @param {ServerResponse} res The server response object
     * @param {function} next The next middleware function in the stack
     */
    static beforeLogin(req, res, next) {
        this.log('info', `Middleware called before auth.post`);
        passport.authenticate('local', { session: true }, (error, user) => {
            if (error) return next(error);

            let token = jwt.sign({username: user.email},
                'dummy',
                { expiresIn: '24h' } // expires in 24 hours
            );
            // return the JWT token for the future API calls
            return new Responder(res).success({ statusCode: 200, token: token });
        })(req, res, next);
    }
    /**
     * Called after login attempt
     * @param {ClientRequest} req The client request object
     * @param {ServerResponse} res The server response object
     * @param {function} next The next middleware function in the stack
     */
    static afterLogin(req, res, next) {
        this.log('info', `Middleware called after auth.post`);
        next();
    }
    static checkToken(req, res, next) {
        let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
        if (token && token.startsWith('Bearer ')) {
            // Remove Bearer from string
            token = token.slice(7, token.length);
        }
        this.log('info', token);

        if (token) {
            jwt.verify(token, 'dummy', (err, decoded) => {
                if (err) {
                    return new Responder(res).error({ statusCode: Responder.StatusCodes.Error.Authenticate, error: 'Token is not valid' });
                } else {
                    req.decoded = decoded;
                    next();
                }
            });
        } else {
            return new Responder(res).error({ statusCode: Responder.StatusCodes.Error.Authenticate, error: 'Authentication failed' });
        }
    }
}

module.exports = Middleware;