#!/usr/bin/env node

import express from 'express'
import bodyParser from 'body-parser';
import session from "express-session";
import { MongoClient } from 'mongodb'
import MongoStore from 'connect-mongo'
import conf from "./conf.js";
import * as cas_server from "./lib/cas_server.js";

function throw_(e) { throw e }
const app = express();

if (conf.trust_proxy) app.set('trust proxy', conf.trust_proxy)

const base_path = new URL(conf.our_base_url).pathname
app.use(base_path, express.static(import.meta.dirname + '/public'));
app.use(base_path + '/javascripts/jquery', express.static(import.meta.dirname + '/node_modules/jquery/dist'));

app.use(bodyParser.urlencoded({ extended: false }));

let mongo_collection
let _mongo_client
const mongo_client = async () => {
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

if(!conf.session_store.mongoUrl) {
    throw_("unknown session_store");
}
const store = MongoStore.create({
    clientPromise: mongo_client(),
    stringify: false,
    ttl: conf.ticket_validity_seconds, // short ttl that will be 
});
app.use(session({ 
    store,
    cookie: { path: base_path, secure: 'auto', sameSite: 'none' },
    resave: false, saveUninitialized: false,
    ...conf.session_store.options,
}));

app.set('views', import.meta.dirname + '/views');
app.set("view engine", "ejs");

app.use(base_path, cas_server.routing());

for (const plugin in conf.plugins) {
    await import(`./lib/plugins/${plugin}.js`)
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
