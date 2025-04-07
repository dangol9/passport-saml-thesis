const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: '',
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new SamlStrategy(
  {
    path: '/login/callback',
    entryPoint: '',
    issuer: 'http://localhost:3000/',
    cert: ''
  },
  function (profile, done) {
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`<h1>Hello, ${req.user.nameID}</h1><a href="/logout"><button>Logout</button></a>`);
  } else {
    res.send('<a href="/login"><button>Login with SAML</button></a>');
  }
});

app.get('/login',
  passport.authenticate('saml', {
    failureRedirect: '/',
  })
);

app.post('/login/callback',
  passport.authenticate('saml', {
    failureRedirect: '/',
  }),
  (req, res) => {
    res.redirect('/');
  }
);

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
