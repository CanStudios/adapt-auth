const { AbstractModule, DataStoreQuery } = require('adapt-authoring-core');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const AuthUtility = require('./utility.js');
/**
 * Adds authentication + authorisation to the server
 * @extends {AbstractModule}
 */
class AuthModule extends AbstractModule {
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

        app.dependencyloader.on('preload', () => {
            app.auth.scopes.forEach(s => {
                s = s.replace(':','.');
                router.addRoute({
                    route: `/${s}`,
                    handlers: { get: (req, res) => res.send(s) }
                });
            });
        });

        app.auth.unsecureRoute('auth', 'POST');

        server.requestHook.tap(this.handleRequest.bind(this));

        resolve();
    }
    /** @override*/
    boot(app, resolve, reject) {
        super.boot(app, () => {
            passport.use(new LocalStrategy({
                usernameField: 'email',
                passwordField: 'password'
            }, (username, password, done) => {
                const dsquery = new DataStoreQuery({ "fieldsMatching": { "email": username }, "type": "user" });
                app.getModule('mongodb')['retrieve'](dsquery).then(user => {
                    if (!user[0]) return done(new Error(app.getModule('lang').t(`error.${"invalidemailpassword"}`)));

                    return done(null, user);
                }).catch(e => done(e));
            }));

            passport.serializeUser((user, done) => {
                user = user[0];
                done(null, {
                    _id: user._id,
                    email: user.email
                });
            });

            passport.deserializeUser((user, done) => {
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
     * Handles passport authentication, returns JWT if authentication is successful
     * @param req
     * @param res
     * @param next
     */
    login(req, res, next) {
        passport.authenticate('local', { session: true }, (error, user) => {
            if (error) return next(error);

            let token = jwt.sign({username: user.email},
                'dummy',
                { expiresIn: '24h' } // expires in 24 hours
            );
            // return the JWT token for the future API calls
            return res.status(200).json({ token: token });
        })(req, res, next);
    }

    /**
     * Verifies the current request can access the requested resource
     * @param {ClientRequest} req
     * @return {Promise}
     */
    handleRequest(req) {
        return AuthUtility.isAuthenticated(req);
    }
}

module.exports = AuthModule;