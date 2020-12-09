const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const connection = require('./db')
const User = connection.models.User
const validPassword = require('../utils/password').validPassword

const customFields = {
  usernameField: 'uname',
  passwordField: 'pw'
}

const verifyCallback = (username, password, done) => {
  User.findOne({ username: username })
    .then(user => {
      if (!user) {
        return done(null, false)
      }

      const isValid = validPassword(password, user.hash, user.salt)

      if (isValid) {
        return done(null, false)
      } else {
        return done(null, user)
      }
    })
    .catch(err => {
      done(err)
    })
}

const strategy = new LocalStrategy(customFields, verifyCallback)

passport.use(strategy)

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser((userId, done) => {
  User.findById(userId)
    .then(user => {
      done(null, user)
    })
    .catch(err => done(err))
})
