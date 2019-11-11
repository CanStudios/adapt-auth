const AuthUtils = require('./utility');
const Middleware = require('./middleware');
const Controller = require('./controller');
const { AbstractModule, DataStoreQuery } = require('adapt-authoring-core');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');
/**
 * Adds authentication + authorisation to the server
 * @extends {AbstractModule}
 */
class AuthModule extends AbstractModule {
    /** @override */
    static get def() {
        return {
            name: 'auth',
            routes: [
                {
                    route: '/:id?',
                    handlers: ['post', 'get']
                }
            ]
        };
    }

    /** @override*/
    preload(app, resolve, reject) {
        const server = app.getModule('server');
        const router = server.api.createChildRouter('auth');

        router.addRoute({
          route: '/:login?',
          handlers: { post: this.login.bind(this) }
        });
        server.use(cookieParser('prototype-secret'));
        server.use(bodyParser.json({ limit: '5mb' }));
        server.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
        server.use(session({
            key: 'connect.sid',
            secret:'prototype-secret',
            resave: false,
            cookie: {
                signed: true,
                secureProxy: false
            },
            saveUninitialized: true
        }));
        server.use(passport.initialize());
        server.use(passport.session());

        this.log('info', app.auth.scopes);

        app.dependencyloader.on('preload', () => {
            app.auth.scopes.forEach(s => {
                s = s.replace(':','.');
                router.addRoute({
                    route: `/${s}`,
                    handlers: { get: (req, res) => res.send(s) }
                });
                app.auth.secureRoute(`${router.path}/${s}`, 'get', ['read:auth']);
            });
        });
        //server.requestHook.tap(this.handleRequest.bind(this));

        resolve();
    }
    /** @override*/
    boot(app, resolve, reject) {
        super.boot(app, () => {

            passport.use(new LocalStrategy({
                usernameField: 'email',
                passwordField: 'password'
            }, (username, password, done) => {
                this.log('info', 'username: ' + username + ' password: ' + password);
                done();
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
                const dsquery = new DataStoreQuery( {"_id":user._id,"type":"user"} );
                app.getModule('mongodb')['retrieve'](dsquery).then(user => {
                    if (!user) return done(new Error(`${Errors.Deserialize}`));
                    done(null, user[0]);
                }).catch(e => done(e));
            });

            resolve();
        }, reject);
    }
    /**
     * Verifies the current request can access the requested resource
     * @param req
     * @param res The response object
     * @param {Function} next The next middleware
     * @return {Promise}
     */
    handleRequest(req) {
        return AuthUtils.authenticate(req, res, next);
    }

    login(req, res, next) {
        passport.authenticate('local', { session: true }, (error, user) => {
            if (error) return next(error);

            let token = jwt.sign({username: user.email},
                'dummy',
                { expiresIn: '24h' } // expires in 24 hours
            );
            // return the JWT token for the future API calls
            return new Responder(res).success({ statusCode: 200, token: token });
        })(req, res, next);
    }
}

module.exports = AuthModule;