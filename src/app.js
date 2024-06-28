const { web } = require("../secrets.json");
const http = require('http');
const https = require('https');
const url = require('url');
const { google } = require('googleapis');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('node:path');
const ejs = require('ejs');
const db = require('./db/model.js');

const oauth2Client = new google.auth.OAuth2(
  web.client_id,
  web.client_secret,
  web.redirect_uris[0]
);

const scopes = [
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/userinfo.email',
];

async function refreshTokenIfNeeded(req, res, next) {
  if (!req.session.tokens) {
    return next();
  }

  const now = Date.now();
  const expiryDate = req.session.tokens.expiry_date;

  if (expiryDate && now >= expiryDate - 60000) {
    try {
      const tokens = await oauth2Client.refreshAccessToken();
      req.session.tokens.access_token = tokens.credentials.access_token;
      req.session.tokens.expiry_date = tokens.credentials.expiry_date;
      
      oauth2Client.setCredentials({
        access_token: tokens.credentials.access_token,
        expiry_date: tokens.credentials.expiry_date
      });

      console.log("Funciona el expiry_date");

      req.session.save(err => {
        if (err) {
          console.error('Error saving session:', err);
          return res.sendFile(path.join(__dirname, "front", "index.html"));
        }
        next();
      });
    } catch (error) {
      console.error('Error refreshing access token', error);
      return res.sendFile(path.join(__dirname, "front", "index.html"));
    }
  } else {
    next();
  }
}

async function main() {
  const app = express();

  app.use(session({
    secret: 'your_secure_secret_key', 
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: 'mongodb://localhost:27017/worklink', 
      ttl: 14 * 24 * 60 * 60,
      collectionName: 'sessions' 
    }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', 
    }
  }));

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(express.static(path.join(__dirname, 'front')));
  app.use(refreshTokenIfNeeded);

  app.get('/signIn', async (req, res) => {
    const state = crypto.randomBytes(32).toString('hex');
    req.session.state = state;
    const authorizationUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      include_granted_scopes: true,
      state: state
    });
    res.redirect(authorizationUrl);
  });

  app.get('/oauth2callback', async (req, res) => {
    const q = url.parse(req.url, true).query;
    if (q.state) {
      if (q.error) {
        console.log('Error:' + q.error);
        res.sendFile(path.join(__dirname, 'front', 'index.html'));
      } else if (q.state !== req.session.state) {
        console.log('State mismatch. Possible CSRF attack');
        res.sendFile(path.join(__dirname, 'front', 'index.html'));
      } else {
        let { tokens } = await oauth2Client.getToken(q.code);
        req.session.tokens = tokens;

        if (tokens.refresh_token) {
          await oauth2Client.verifyIdToken({
            idToken: tokens.id_token,
            audience: web.client_id,
          })
          .then(async data => {
            let email = await data.payload.email;
            db.createOAuthUser(email, tokens.refresh_token)
          })
        } else {
          await oauth2Client.verifyIdToken({
            idToken: tokens.id_token,
            audience: web.client_id,
          })
          .then(async data => {
            let oauthuser = await db.findOAuthUserByEmail(data.payload.email)
            oauth2Client.setCredentials({
              refresh_token: oauthuser.refresh_token,
            })
            req.session.tokens.refresh_token = oauthuser.refresh_token;
          })
        }

        // // Forzar la expiración rápida para pruebas
        // req.session.tokens.expiry_date = Date.now() + 10000; // 10 segundos

        oauth2Client.setCredentials(req.session.tokens);

        const oauth2 = google.oauth2({
          auth: oauth2Client,
          version: 'v2'
        });

        const { data } = await oauth2.userinfo.get();
        res.render('index', { data });
      }
    } else {
        oauth2Client.setCredentials(req.session.tokens);

        const oauth2 = google.oauth2({
          auth: oauth2Client,
          version: 'v2'
        });

        const { data } = await oauth2.userinfo.get(); 
        res.render('index', { data });
    }
  });

  app.get('/protected', async (req, res) => {
    if (!req.session.tokens) {
      return res.redirect('/signIn');
    }

    oauth2Client.setCredentials(req.session.tokens);

    try {
      const oauth2 = google.oauth2({
        auth: oauth2Client,
        version: 'v2'
      });

      const { data } = await oauth2.userinfo.get(); 
      res.render('index', { data });
    } catch (error) {
      console.error('Error accessing protected resource', error);
      res.redirect('/signIn');
    }
  });

  app.get('/revoke', async (req, res) => {
    try {
      oauth2Client.revokeCredentials();
      res.sendFile(path.join(__dirname, 'front', 'index.html'));
    } catch {
      res.sendFile(path.join(__dirname, 'front', 'index.html'));
    }
  });

  http.createServer(app).listen(8080, () => {
    console.log('Server is running on http://localhost:8080');
  });
}

main().catch(console.error);
