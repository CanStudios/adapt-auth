const { App, DataStoreQuery } = require('adapt-authoring-core');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const Errors = require('../lib/errors');
const bcrypt = require('bcrypt-nodejs');
const Logger = require('adapt-authoring-logger');

class Local {
    /**
     * Sets up passports local strategy, serialization and de-serialization.
     */
    init() {
        passport.initialize();
        passport.session();

        passport.serializeUser((user, done) => {
            Logger.log('info', 'serializeUser');
            done(null, {
                _id: user._id,
                email: user.email
            });
        });

        passport.deserializeUser((user, done) => {
            Logger.log('info', 'deserializeUser');
            const dsquery = new DataStoreQuery( {"_id":user._id,"type":"user"} );
            App.instance.getModule('mongodb')['retrieve'](dsquery).then(user => {
                if (!user) return done(new Error(`${Errors.Deserialize}`));

                done(null, user);
            }).catch(e => done(e));
        });

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
    }
}

module.exports = Local;
