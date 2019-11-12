const { AbstractUtility, App, Utils, Responder } = require('adapt-authoring-core');
const jwt = require('jsonwebtoken');
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
     * @param req The client request object
     */
    static isAuthenticated(req) {
        App.instance.logger.log(App.instance.auth.routes)

        App.instance.logger.log(App.instance.auth.routes.unsecure[req.originalUrl.replace("/api/", "")])

        //App.instance.logger.log(App.instance.auth.routes.unsecure[req.originalUrl.replace("/api/", "")][req.method])


        return new Promise((resolve, reject) => {
            // Determine whether authentication is required
            //let methodType = (req.method === 'GET') ? 'read' : 'write';
            //let requiresAuthentication = App.instance.auth.scopes.includes(methodType + ':' + req.originalUrl.replace("/api/", ""));

            let unsecureRoute = App.instance.auth.routes.unsecure[req.originalUrl.replace("/api/", "")]

            // If no authentication is required then resolve
            if (unsecureRoute && unsecureRoute[req.method.toLowerCase()]) return resolve();

            // Authentication is required so check token
            let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
            if (token && token.startsWith('Bearer ')) {
                // Remove Bearer from string
                token = token.slice(7, token.length);
            }

            if (token) {
                jwt.verify(token, 'dummy', (err, decoded) => {
                    if (err) {
                        reject(new Error('Token is not valid' ));
                    } else {
                        req.decoded = decoded;
                        resolve();
                    }
                });
            } else {
                reject(new Error('Authentication failed'));
            }
        });
    }
}
/** @ignore*/
function setRoute(method, route, routes, value) {
    method = method.toLowerCase();

    if (route.substr(-1) === '/') {
        route = route.substr(0, route.length - 1);
    }

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