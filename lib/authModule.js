const AuthUtils = require('./utility');
const { AbstractModule, DataStoreQuery, Responder } = require('adapt-authoring-core');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
/**
 * Adds authentication + authorisation to the server
 * @extends {AbstractModule}
 */
class AuthModule extends AbstractModule {
    /** @override*/
    preload(app, resolve, reject) {
        this.log('info', 'auth module preload')
        const server = app.getModule('server');
        const r = server.api.createChildRouter('auth');
        this.log('info', '1')
        app.use(cookieParser('prototype-secret'));
        this.log('info', '2')
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
                r.addRoute({
                    route: `/${s}`,
                    handlers: { get: (req, res) => res.send(s) }
                });
                app.auth.secureRoute(`${r.path}/${s}`, 'get', ['read:auth']);
            });
        });
        server.requestHook.tap(this.handleRequest.bind(this));

        resolve();
    }
    /** @override*/
    boot(app, resolve, reject) {
        super.boot(app, () => {
            this.log('info', 'inside auth boot');

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
     * @param {ClientRequest} req
     * @return {Promise}
     */
    handleRequest(req) {
        this.log('info', 'handling auth request');
        return AuthUtils.authenticate(req).then(() => AuthUtils.authorise(req));
    }
}

module.exports = AuthModule;