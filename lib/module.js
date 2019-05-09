const {Module} = require('adapt-authoring-core');
const api = require('./api');

/**
* Adds passport-based authentication to the application.
* @extends {Module}
*/
class Auth extends Module {
  /**
  * Adds the middleware
  */
  preload(app, resolve, reject) {
    this.initApi();
    resolve();
  }
  /**
   * Creates and initialises the API
   */
  initApi() {
    this.app.getModule('server').createApi('auth')
      .setRoutes(api)
      .init();
  }
}

module.exports = Auth;
