const {Module} = require('adapt-authoring-core');
const api = require('./api');
const Local = require('../config/local');
const session = require('express-session');
const Logger = require('adapt-authoring-logger');

/**
* Adds passport-based authentication to the application.
* @extends {Module}
*/
class Auth extends Module {
  /**
  * Adds the middleware
  */
  preload(app, resolve, reject) {
    resolve();
  }
  /**
   * @param {App} app App instance
   * @param {Function} resolve Function to call on fulfilment
   * @param {Function} reject Function to call on rejection
   */
  boot(app, resolve, reject) {
      this.initApi(app);
      app.getModule('server').use(session({
          secret: 'prototype-secret',
          resave: false,
          saveUninitialized: false
      }));
      const local = new Local();
      local.init();
      resolve();
  }
  /**
   * Checks that the user has permission to access the API
   * @param {ClientRequest} req The client request object
   * @param {ServerResponse} res The server response object
   * @param {function} next The next middleware function in the stack
   */
  authenticate(req, res, next) {
      Logger.log('info', `Testing authentication for ${req.originalUrl} and the session was`);
      Logger.log('info', JSON.stringify(req.session));
      return next();
  }
  /**
   * Creates and initialises the API
   */
  initApi(app) {
      app.getModule('server').addApiMiddleware(this.authenticate.bind(this));
      app.getModule('server').createApi('auth')
      .setRoutes(api)
      .init();
  }
}

module.exports = Auth;
