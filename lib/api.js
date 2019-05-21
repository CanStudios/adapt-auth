const Controller = require('./controller');
const Middleware = require('./middleware');
/** @ignore */
const routes = [
    {
        route: '/:login?',
        handlers: {
            post: [Middleware.beforeLogin, Controller.postLogin, Middleware.afterLogin],
            get: [Controller.getLogin]
        }
    }
];

module.exports = routes;