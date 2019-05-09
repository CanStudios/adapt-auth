const Logger = require('adapt-authoring-logger');
const DataStoreQuery = require('adapt-authoring-core');
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
    static beforePost(req, res, next) {
        log('info', `Middleware called before auth.post`);
        next();
    }
    /**
     * Called after login attempt
     * @param {ClientRequest} req The client request object
     * @param {ServerResponse} res The server response object
     * @param {function} next The next middleware function in the stack
     */
    static afterPost(req, res, next) {
        log('info', `Middleware called after auth.post`);
        next();
    }
};
/** @ignore */
function log(level, ...rest) {
    Logger.log(level, 'auth-middleware', ...rest);
}

module.exports = Middleware;
