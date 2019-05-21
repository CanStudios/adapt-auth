const Logger = require('adapt-authoring-logger');
const DataStoreQuery = require('adapt-authoring-core');
const passport = require('passport');
/**
 * Middleware for the auth module
 */
class Middleware {
    /**
     * Called before login attempt
     * @param {ClientRequest} req The client request object
     * @param {ServerResponse} res The server response object
     * @param {function} next The next middleware function in the stack
     */
    static beforeLogin(req, res, next) {
        log('info', `Middleware called before auth.post`);
        passport.authenticate('local', { session: true }, (error, user) => {
            if (error) return next(error);

            req.login(user, (error) => {
                if (error) return next(error);

                return next();
            });
        })(req, res, next);
    }
    /**
     * Called after login attempt
     * @param {ClientRequest} req The client request object
     * @param {ServerResponse} res The server response object
     * @param {function} next The next middleware function in the stack
     */
    static afterLogin(req, res, next) {
        log('info', `Middleware called after auth.post`);
        next();
    }
};
/** @ignore */
function log(level, ...rest) {
    Logger.log(level, 'auth-middleware', ...rest);
}

module.exports = Middleware;
