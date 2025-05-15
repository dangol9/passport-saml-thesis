const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const bodyParser = require('body-parser');
const { sanitize } = require('express-xss-sanitizer');
const lusca = require('lusca');
const fs = require('fs');
const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

app.use(bodyParser.urlencoded({ extended: false }));

app.use(session({
  name: 'Session_ID',
  secret: '{secret}',
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    maxAge: 28800000,
    secure: true,
    httpOnly: true
  }
}));

app.use((req, res, next) => { 
  res.setHeader('Strict-Transport-Security', 'max-age=63072000');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';");
next(); 
});

app.use(passport.initialize());
app.use(passport.session());

passport.use(new SamlStrategy(
  {
    path: '/login/callback',
    entryPoint: '{entryPoint}',
    issuer: '{issuer}', 
    cert: fs.readFileSync('{okta_cert_file}', 'utf-8'),
    decryptionPvk: fs.readFileSync('{pvk_file}', 'utf-8'),
    acceptedClockSkewMs: -240000,
    validateInResponseTo: true
  },
  (profile, done) => {
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

const CSRFSetting = (req, res, next) => { 
  if (req.method === 'POST' && req.path === '/login/callback') { 
    return next(); 
  } 
  return lusca.csrf()(req, res, next); 
} 

app.use(CSRFSetting); 

app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    req.user.nameID = sanitize(req.user.nameID);
    req.user.department = sanitize(req.user.department);
    res.status(200);
    res.send(`<h1>Hello, ${req.user.nameID}! Your department is: ${req.user.department}</h1><form action="/logout" method="POST"><input type='hidden' name='_csrf' value='${req.csrfToken()}'><button>Logout</button></form>`);
  } else {
    res.status(200);
    res.send('<a href="/login"><button>Login with SAML</button></a>');
  }
});

app.get('/login',
  passport.authenticate('saml', {
    failureRedirect: '/',
  })
);

app.get('/login/callback', (req, res) => {
    res.status(401);
    res.send('Unauthorized');
  }
);

app.post('/login/callback',
  passport.authenticate('saml', {
    failureRedirect: '/',
  }),
  (req, res) => {
    res.redirect('/');
    }
);

app.post('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

app.use((req, res) => { 
  res.status(404);
  res.send('Not found'); 
}); 

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
