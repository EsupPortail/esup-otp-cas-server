#!/usr/bin/env node

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session')
const conf = require('./conf');

function throw_(e) { throw e }
const app = express();

if (conf.trust_proxy) app.set('trust proxy', conf.trust_proxy)

const base_path = new URL(conf.our_base_url).pathname
app.use(base_path, express.static(__dirname + '/public'));
app.use(base_path + '/javascripts', express.static(__dirname + '/node_modules/jquery/dist'));

app.use(bodyParser.urlencoded({ extended: false }));
const store = conf.session_store.mongoUrl ? require('connect-mongo').create({
    mongoUrl: conf.session_store.mongoUrl,
    stringify: false,
    ttl: conf.ticket_validity_seconds, // short ttl that will be 
}) : throw_("unknown session_store") ;
app.use(session({ 
    store,
    cookie: { path: base_path, secure: 'auto', sameSite: 'none' },
    resave: false, saveUninitialized: false,
    ...conf.session_store.options,
}));

app.set('views', __dirname + '/views');
app.set("view engine", "ejs");

app.use(base_path, require('./lib/cas_server')());


const port = process.env.PORT || conf.port || '3001'
console.log('Starting on port ' + port);
app.listen(port, process.env.IP);
