const { Responder } = require('adapt-authoring-core');

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
        if(!req.body) {
            const e = new Error(`${Errors.InvalidEmailPassword}`);
            e.statusCode = Responder.StatusCodes.Error.Authenticate;
            return next(e);
        }
        const responder = new Responder(res);
        const args = [];

        if(req.dsquery) args.push(req.dsquery);
        if(req.body) args.push(req.body);

        return responder.success({ statusCode: 200 });
    }
    /**
     * Get login page
     */
    static getLogin(req, res, next) {
        const responder = new Responder(res);
        const args = [];

        if(req.dsquery) args.push(req.dsquery);
        if(req.body) args.push(req.body);

        return responder.success({ statusCode: 200 });
    }
}

module.exports = Controller;