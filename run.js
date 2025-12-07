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
app.use(base_path + '/javascripts/jquery', express.static(__dirname + '/node_modules/jquery/dist'));

app.use(bodyParser.urlencoded({ extended: false }));

let mongo_collection
let _mongo_client
const mongo_client = async () => {
    const { MongoClient } = require('mongodb')
    const client = _mongo_client = await MongoClient.connect(conf.session_store.mongoUrl)
    mongo_collection = client.db().collection('sessions')
    await mongo_collection.createIndex({ "session.ticket_for_SLO": 1 }, { background: true, expireAfterSeconds: 0 })
    await mongo_collection.createIndex({ "session.uid": 1 }, { background: true, expireAfterSeconds: 0 })
    return client
}
app.use((req, _res, next) => {
    req.mongo_collection = mongo_collection
    next()
})

const store = conf.session_store.mongoUrl ? require('connect-mongo').create({
    clientPromise: mongo_client(),
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

app.use(base_path, require('./lib/cas_server').routing());

for (const plugin in conf.plugins) {
    require(`./lib/plugins/${plugin}`)
}

const port = process.env.PORT || conf.port || '3001'
console.log('Starting on port ' + port);
let server = app.listen(port, process.env.IP);

process.on('SIGTERM', function() {
    console.info('Stopping...')
    server?.close((err) => {
        // all requests are now finished
        if (err) console.error("Stopping HTTP server failed", err)
        _mongo_client?.close()
        console.info('Stopped')
        process.exit(0)
    })
    server = undefined // avoir errors if SIGTERM is received multiple times
});
