const { AbstractUtility, App, Utils } = require('adapt-authoring-core');
/**
 * Utility to handle authentication + authorisation
 */
class AuthUtility extends AbstractUtility {
    /**
     * @constructor
     * @param {App} app Main App instance
     * @param {Object} pkg Package.json data
     */
    constructor(app, pkg) {
        super(app, pkg);
        /**
         * The routes registered with the auth utility
         * @type {Object}
         */
        this.routes = {};
        const routes = { secure: {}, unsecure: {} };
        Utils.defineGetter(this, 'routes', routes);
        /**
         * The registered authorisation scopes
         * @type {Array}
         */
        this.scopes = [];
        const scopes = [];
        Utils.defineGetter(this, 'scopes', scopes);
        /**
         * Restricts access to a route/endpoint
         * @note All endpoints are blocked by default
         * @type {Function}
         * @param {String} route The route/endpoint to secure
         * @param {String} method HTTP method to block
         * @param {Array} scope The scope(s) to restrict
         */
        this.secureRoute = (route, method, scope) => {
            if(!Array.isArray(scope)) {
                scope = [scope];
            }
            scope.forEach(s => !scopes.includes(s) && scopes.push(s));

            if(routes.secure[route] && routes.secure[route][method]) {
                return warn('alreadysecure', method, route);
            }
            setRoute(method, route, routes.secure, scope);
        }
        /**
         * Allows unconditional access to a specific route
         * @type {Function}
         * @param {String} route The route/endpoint
         * @param {String} method HTTP method to allow
         */
        this.unsecureRoute = (route, method) => {
            setRoute(method, route, routes.unsecure, true);
        }
    }

    /**
     * Checks that the user has permission to access the API
     * @param {ClientRequest} req The client request object
     * @param {ServerResponse} res The server response object
     * @param {function} next The next middleware function in the stack
     */
    static authenticate(req, res, next) {
        let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
        if (token && token.startsWith('Bearer ')) {
            // Remove Bearer from string
            token = token.slice(7, token.length);
        }
        this.log('info', token);

        if (token) {
            jwt.verify(token, config.secret, (err, decoded) => {
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
/** @ignore*/
function setRoute(method, route, routes, value) {
    method = method.toLowerCase();
    //route = AuthUtils.removeTrailingSlash(route);

    if(!['post','get','put','patch','delete'].includes(method)) {
        return warn('secureroute', method, route);
    }
    if(!routes[route]) {
        routes[route] = {};
    }
    routes[route][method] = value;
}
/** @ignore */
function warn(key, method, route) {
    App.instance.logger.log('warn', 'auth-utility', App.instance.lang.t(`error.${key}`, { method, route }));
}

module.exports = AuthUtility;