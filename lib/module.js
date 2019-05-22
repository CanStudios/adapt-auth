const {Module} = require('adapt-authoring-core');
const api = require('./api');
const { App, DataStoreQuery } = require('adapt-authoring-core');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const Errors = require('../lib/errors');
const bcrypt = require('bcrypt-nodejs');
const Logger = require('adapt-authoring-logger');
const Middleware = require('./middleware');

/**
* Adds passport-based authentication to the application.
* @extends {Module}
*/
class Auth extends Module {
  /**
  * Adds the middleware
  */
  preload(app, resolve, reject) {
    app.getModule('server').addApiMiddleware(this.handleUserCreate.bind(this));
    resolve();
  }
  /**
   * @param {App} app App instance
   * @param {Function} resolve Function to call on fulfilment
   * @param {Function} reject Function to call on rejection
   */
  boot(app, resolve, reject) {
      passport.use(new LocalStrategy({
          usernameField: 'email',
          passwordField: 'password'
      }, (username, password, done) => {
          const dsquery = new DataStoreQuery({"email":username,"type":"user"});
          App.instance.getModule('mongodb')['retrieve'](dsquery).then(user => {
              if (!user) return done(new Error(`${Errors.InvalidEmailPassword}`));

              bcrypt.compare(password, user[0].password, (error, valid) => {
                  if (error || !valid) return done(new Error(`${Errors.InvalidEmailPassword}`));

                  return done(null, user);
              });
          }).catch(e => done(e));
      }));

      passport.serializeUser((user, done) => {
          Logger.log('info', 'serializeUser');
          user = user[0];
          done(null, {
              _id: user._id,
              email: user.email
          });
      });

      passport.deserializeUser((user, done) => {
          Logger.log('info', 'deserializeUser');
          Logger.log('info', new Error().stack);
          const dsquery = new DataStoreQuery( {"_id":user._id,"type":"user"} );
          App.instance.getModule('mongodb')['retrieve'](dsquery).then(user => {
              if (!user) return done(new Error(`${Errors.Deserialize}`));
              done(null, user[0]);
          }).catch(e => done(e));
      });

      this.initApi(app);
      resolve();
  }
  /**
   * Creates and initialises the API
   */
  initApi(app) {
      app.getModule('server').createApi('auth')
      .setRoutes(api)
      .init();
  }
  static initialize() {
      return passport.initialize();
  }
  static session() {
      return passport.session();
  }
  /**
   * Hashes a password
   * @param {password} plaintext password for hashing
   * @param {next} callback function
   */
  hashPassword(password, next) {
      bcrypt.genSalt(10, function(err, salt) {
          bcrypt.hash(password, salt, null, next);
      });
  }
  /**
   * Checks that the user has permission to access the API
   * @param {ClientRequest} req The client request object
   * @param {ServerResponse} res The server response object
   * @param {function} next The next middleware function in the stack
   */
  static authenticate(req, res, next) {
      return Middleware.checkToken(req, res, next);
  }
  /**
   * If this is a user post request then hash password before continuing
   * @param req
   * @param res
   * @param next
   */
  handleUserCreate(req, res, next) {
    if (req.originalUrl === '/api/users' && req.method === 'POST') {
        this.log('info', 'Detected user creation');
        this.hashPassword(req.body.password, (error, hash) => {
            if (error) {
                const e = new Error(`${Errors.HashFail}`);
                e.statusCode = Responder.StatusCodes.Error.Auth;
                return next(e);
            }
            req.body.password = hash;
            return next();
        });
    } else {
        return next();
    }
  }
}

module.exports = Auth;
