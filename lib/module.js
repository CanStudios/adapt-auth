const {Module} = require('adapt-authoring-core');

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
}

module.exports = Auth;
