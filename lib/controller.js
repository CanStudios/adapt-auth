const { DataStoreQuery, Responder } = require('adapt-authoring-core');
const lib = require('./lib');

/**
 * Controller for the auth API
 */
class Controller {
    /**
     * Attempt login
     * @param {ClientRequest} req The client request object
     * @param {ServerResponse} res The server response object
     * @param {function} next The next middleware function in the stack
     */
    static postLogin(req, res, next) {
    }
    /**
     * Get login page
     */
    static getLogin(req, res, next) {
        execFunc('get', req, res, next);
    }
};
/**
 * Convenience method to executes a passed function
 * @param {String} func Name of the function to be called
 * @param {ClientRequest} req The client request object
 * @param {ServerResponse} res The server response object
 * @param {function} next The next middleware function in the stack
 */
function execFunc(func, req, res, next) {
    const responder = new Responder(res);
    const args = [];

    if(req.dsquery) args.push(req.dsquery);
    if(req.body) args.push(req.body);

    return responder.success({ statusCode: 200 });
}


module.exports = Controller;
