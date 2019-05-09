const Controller = require('./controller');
const Middleware = require('./middleware');
/** @ignore */
const routes = [
    {
        route: '/:login?',
        handlers: {
            post: [Middleware.beforePost, Controller.postLogin, Middleware.afterPost],
            get: [Controller.getLogin]
        }
    }
];

module.exports = routes;