const passport = require('passport')
const JWT = require('jsonwebtoken')
const PassportJWT = require('passport-jwt')
const User = require('../models/User')

const jwtSecret = process.env.JWT_SECRET

passport.use(User.createStrategy())

const signUp = (req, res, next) => {

  if (!req.body.email || !req.body.password) {
    res.status(400).send('No username or password provided.')
  }

  const user = new User({
    email: req.body.email,
    firstName: req.body.firstName,
    lastName: req.body.lastName
  })

  User.register(user, req.body.password, (error, user) => {
    if (error) {
      next(error)
      return
    }
  })

  req.user = user
  next()
}

const signJWTForUser = (req, res) => {
  const user = req.user
  const token = JWT.sign(
    {
      email: user.email
    },
    jwtSecret,
    {
      expiresIn: "3 hours"
    }
  );
  res.json({ token })
}

passport.use(
  new PassportJWT.Strategy(
    {
      jwtFromRequest: PassportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtSecret
    },
    (payload, done) => {
      User.findById(payload.sub)
        .then(user => {
          if (user) {
            done(null, user)
          } else {
            done(null, false)
          }
        })
        .catch(error => {
          done(error, false)
        })
    }
  )
)

const tokenValidator = (token = "") => {
  try {
    return JWT.verify(token, jwtSecret);
  } catch (e) {
    console.error(e);
    return false;
  }
}

const requireJWT = (req, res, next) => {
  const jwt = req.header("Authorization");
  if (tokenValidator(jwt)) {
    next();
  } else {
    res.status(401).send("unauthorized");
  }
}

module.exports = {
  initialize: passport.initialize(),
  signUp,
  signIn: passport.authenticate('local', { session: false }),
  requireJWT,
  signJWTForUser
}
