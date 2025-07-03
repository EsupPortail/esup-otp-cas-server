const querystring = require('querystring')
const express = require('express');
const fetch = require('node-fetch')
const qrcode = require('qrcode');

const cond_no_otp = require('./cond_no_otp')
const h = require('./helpers')
const conf = require('../conf')

/** @typedef {{ uid: string, raw_response: string }} v2_response */
/** @typedef {{ uid: string, service: string, v2_response?: v2_response, date: number, sessionID: string, addServiceHashtoPath: boolean }} ticket_info */

/** @typedef {{}} empty_session */
/** @typedef {{ uid: string, validated_uid: Date, ticket_for_SLO: string, ticket_to_v2_response: Object.<string, v2_response> }} session_but_not_validated (ticket consumed) */
/** @typedef {{ uid: string, validated_uid: Date, ticket_for_SLO: string, attrs?: Object.<string, string[]>, validated_FranceConnect_AND_password?: true, validated_otp: Date, long_term_otp: boolean }} session_validated */



const html_remove_ticket_script = `<script>
window.history.replaceState({}, null, location.href.replace(/[?&]ticket=.*/, ''))
</script>`
const validateErrorXml = `<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
<cas:authenticationFailure code="INVALID_TICKET">
</cas:authenticationFailure>
</cas:serviceResponse>`;

/** @param {string} service */
const simplify_service_url = (service) => (
    service
        .replace(/(%|%25)3A/g, ':')
        .replace(/(%|%25)2F/g, '/')
)

// removing ";jsessionid=..." is not clearly defined in CAS protocol specification, but it is needed!
// (cf "AbstractServiceFactory.cleanupUrl" in Jasig/Apereo CAS, or DefaultServiceComparator.java in Shibboleth IDP)
/** @param {string} service */
const cleanup_service_url = (service) => (
    service.replace(/;jsession[^?]*/, '')
)

const is_service_matching = h.is_service_matching

/** @param {string} service */
const is_service_allowed = (service) => (
    is_service_matching(conf.allowed_services, service)
)

/** @param {{ service: string, renew?: string, ask?: string, ticket?: string, pgtUrl?: string }} query 
 *  @param {boolean=} addServiceHashtoPath */
const ourUrl = (query, addServiceHashtoPath) => (
    conf.our_base_url + '/login' + (addServiceHashtoPath && query.service ? '-' + h.md5(query.service) : '') + '?' + querystring.stringify(query)
)

/**
 * @param {String} uri without starting "/"
 * @param {{}} [opts={}] { method:'POST' } 
 */
function fetchApi(uri, opts = {}) {
    return fetch(conf.api_url_internal + uri, {
        headers: { Authorization: "Bearer " + conf.api_password },
        ...opts,
    })
}

/**
 * @param {String} path
 * @param {import('querystring').ParsedUrlQuery} params
 */
const fetchFromCas = (path, params) => (
    fetch(conf.cas_server_validating_password_base_url_internal + path + "?" + querystring.stringify(params), { 
        compress: false, // workaround "Invalid response body while trying to fetch /cas/serviceValidate". needed for node-fetch version 2.7.0 (was working with 2.6.7)
        signal: AbortSignal.timeout(conf.ticket_validity_seconds * 1000), // no need to wait for a very slow answer since ticket will be invalid anyway
    })
)

/** @param {string} uid
  * @param {string} otp
  * @returns {Promise<string>} */
async function verifyOtp(uid, otp) {
    console.log('verifyOtp', uid, otp)
    const response = await fetchApi('protected/users/' + uid + '/' + otp + '/', {
        method: 'POST',
    })
    const body = await response.text()
    let infos
    try {
        infos = JSON.parse(body)
    } catch (err) {
        console.error("verifyOtp failed. esup-otp-api responded invalid JSON", response.status, body)
       throw "Problème technique, veuillez ré-essayer plus tard."
    }
    if (infos && infos.code === 'Ok') return infos.method
    if (infos && infos.code === 'Error') throw "Le code est invalide."
    console.error("verifyOtp failed. esup-otp-api responded", response.status, infos)
    throw "Problème technique, veuillez ré-essayer plus tard."
}

/** @param {string} service
  * @param {string} ticket
  * @param {boolean} addServiceHashtoPath
  * @returns {Promise<{ uid: string, raw_response: string}>} */
async function casv1_validate_ticket(service, ticket, addServiceHashtoPath) {
    const params = { service: ourUrl({ service }, addServiceHashtoPath) + '&auth_checked', ticket }
    const response = await fetchFromCas('/validate', params)
    if (response.ok) {
        const body = await response.text();
        const [l1, l2] = body.split("\n")
        if (l1 === 'yes') return { uid: l2, raw_response: body }
        if (l2 === 'no') throw { msg: "error" }
    }
    throw { msg: "Problème technique, veuillez ré-essayer plus tard." }
}
/** @param {string} service
  * @param {string} ticket
  * @param {boolean} addServiceHashtoPath
  * @param {string=} pgtUrl
  * @returns {Promise<v2_response>} */
async function casv2_validate_ticket(service, ticket, addServiceHashtoPath, pgtUrl) {
    const params = { service: ourUrl({ service }, addServiceHashtoPath) + '&auth_checked', ticket, pgtUrl }
    const response = await fetchFromCas('/serviceValidate', params)
    if (response.ok) {
        const body = await response.text();
        const m = body.match(/<cas:authenticationSuccess>/) && body.match(/<cas:user>(.*?)<\/cas:user>/)
        if (m) return { uid: h.decodeEntities(m[1]), raw_response: body }
        const err = body.match(/<cas:authenticationFailure code="(.*)">(.*?)</)
        if (err) throw { code: err[1], msg: h.decodeEntities(err[2]), raw_response: body }
    }
    throw { msg: "Problème technique, veuillez ré-essayer plus tard." }
}


/** @param {string} ticket
  * @param {ticket_info} info */
const save_allowed_ticket = (sessionStore, ticket, info) => {
    if (!ticket) { console.trace(); throw "internal error" }
    //console.log('save_allowed_ticket', ticket, info)
    sessionStore.set(ticket, info, (err) => {
        console.log("storing ticket", ticket, "done")
        if (err) console.error(err)
    })
}

/** @param {string} sessionID */
function expire_session_uid(sessionStore, sessionID) {
    sessionStore.get(sessionID, (err, session) => {
        if (err) {
            console.error(err)
        } else {
            sessionStore.set(sessionID, { ...session, validated_uid: new Date(0) })
        }
    })
}

/** @param {string} ticket */
async function expire_session_uid_from_ticket(sessionStore, mongo_collection, ticket) {
    try {
        const entry = await mongo_collection.findOne({ "session.ticket_for_SLO": ticket })
        console.log("logoutRequest ticket_info", entry)
        const sessionID = entry?._id
        if (sessionID) {
            console.log("expiring uid of session", sessionID)
            // NB: keeping "validated_otp" in case user re-log with same user. If different user, "validated_otp" will be ignored
            expire_session_uid(sessionStore, sessionID)
        }
    } catch (err) {
        console.error(err)
    }
}

const sessionStore_get = (sessionStore, id) => (
    new Promise((resolve, reject) => {
        sessionStore.get(id, (err, info) => {
            if (err) {
                console.error(err)
                return reject()
            } else {
                resolve(info)
            }
        })
    })
)

/** @param {string} service
  * @param {string} ticket
  * @returns {Promise<ticket_info>} */
const get_allowed_ticket = async (sessionStore, service, ticket) => {
    const info = await sessionStore_get(sessionStore, ticket)

    if (!info) {
    } else {
        //console.log("removing ticket", ticket, info)
        sessionStore.destroy(ticket) // only once
    }

    if (!info || !info.uid) {
        throw "unknown ticket " + ticket + " for service " + service + " (already validated? or passed directly from cas_server_validating_password to service?)"
    } else if (info.service !== service) {
        throw "invalid service: at login= " + info.service + "  at validate= " + service
    } else if (h.seconds_since(info.date) > conf.ticket_validity_seconds) {
        throw "ticket expired " + ticket + " : issued " + h.seconds_since(info.date) + " seconds ago"
    } else {
        console.log("ticket", ticket, "is valid for uid", info.uid)
        return info
    }
}

/**
 * @param {string} method 
 */
function set_validated_otp(req, method) {
    h.my_log(req, 'valid OTP', { method })
    req.session.validated_otp = new Date()
    // will set session storage validity
    req.session.cookie.maxAge = conf.otp_validity_seconds * 1000
}

/** @param {session_but_not_validated & session_validated} session
  * @param {string} service
  * @param {string} ticket */
async function get_logged_user_in_session(req, session, service, ticket, addServiceHashtoPath) {
    const v2_response = await casv2_validate_ticket(service, ticket, addServiceHashtoPath);
    console.log("used ticket", ticket, "to know the logged user ", v2_response.uid, ". Saving ticket and response ");

    if (session.uid && session.uid !== v2_response.uid) {
        if (session.validated_otp) {
            console.log("dropping OTP for previous user", session.uid)
        }
        console.log(req.ip, "logged user changed", session.uid, "=>", v2_response.uid)
        delete session.validated_otp
        delete session.validated_FranceConnect_AND_password
        delete session.long_term_otp
    }
    session.uid = v2_response.uid;
    session.validated_uid = new Date()
    session.ticket_for_SLO = ticket
    if (v2_response.raw_response.includes('<cas:first_clientName>FranceConnect</cas:first_clientName>')) {
        session.validated_FranceConnect_AND_password = true
    }
    const get_attr_values = (attr) => (
        [...v2_response.raw_response.matchAll(new RegExp(`<cas:${attr}>(.*)<\/cas:${attr}>`, 'g'))].map(m => m[1])
    )
    // allow conf.no_otp / conf.no_otp.if_not_activated_for_user_and to decide based on user attrs
    session.attrs = Object.fromEntries(
        (conf.cas_server_validating_password_attrs_to_keep_in_session ?? [])
            .map(attr => [attr, get_attr_values(attr)])
    )
    
    const amrs = get_attr_values('amr')
    let details = {}
    if (amrs?.includes('mfa')) {
        set_validated_otp(req, 'franceconnect_mfa')
        details.validated_otp_via_FC = true
    }

    if (is_service_matching(conf.proxy_cas_services, service)) {
        // we can not reuse the response since it was done *without* the app pgtUrl
    } else {
        if (!session.ticket_to_v2_response)
            session.ticket_to_v2_response = {};
        session.ticket_to_v2_response[ticket] = v2_response
    }
    return details
}

/** @param {string} uid
  * @param {string} ticket
  * @param {string} error */
async function login_page(res, uid, ticket, error, params) {
    const json = await (await fetchApi('protected/methods/', { method: 'GET' })).json();
    const methods = json.methods;

    res.render('login.ejs', {
        error,
        ticket,
        params: {
            apiUrl: conf.api_url_public,
            uid,
            userHash: h.get_hash(conf.api_users_secret, uid),
            methods: methods,
            ...params,
        },
    })
}

/** @param {string} ticket */
function rememberMe_page(res, ticket) {
    res.render('rememberMe.ejs', { ticket })
}

/** @param {string} service
  * @param {boolean=} gateway */
function require_a_ticket(res, service, gateway) {
    const redirectURL = conf.cas_server_validating_password_base_url_public + '/login?service=' + encodeURIComponent(ourUrl({ service }, true) + '&auth_checked') + (gateway ? '&gateway=true' : '');
    res.redirect(redirectURL);
}

const shouldAddServiceHashtoPath = (req) => (
    req.path.match(/login-/) ? true : false
)

/** @param {string} ticket 
  * @param {boolean} consumed_ticket */
function onLoginSuccess(req, res, ticket, consumed_ticket) {
    const service = req.query.service

    // NB: we remove the whole "ticket_to_v2_response" from session.
    // If parallel logins
    // - the first will consume v2_response
    // - the next one will have to use a new ticket
    const v2_response = ticket && h.getAndDelete(req.session, 'ticket_to_v2_response')?.[ticket]
    if (ticket && consumed_ticket && !v2_response) {
        if (!is_service_matching(conf.proxy_cas_services, service)) {
            console.log("there were parallel logins. ticket", ticket, consumed_ticket, "is forgotten, will require a new one")
        }
        ticket = undefined
    }

    if (!ticket) {
        return require_a_ticket(res, service, req.query.gateway);
    }
    let ticket_info = { 
        uid: req.session.uid, service,
        // if we already validated this ticket, use it
        v2_response,
        date: Date.now(),
        sessionID: req.sessionID,
        addServiceHashtoPath: shouldAddServiceHashtoPath(req),
    }
    save_allowed_ticket(req.sessionStore, ticket, ticket_info);

    if (service) {
        res.redirect(service + (service.includes("?") ? "&" : "?") + "ticket=" + encodeURIComponent(ticket));
    } else {
        res.send("Utilisateur correctement authentifié");
    }
}

/** @param {casv1_validate_ticket | casv2_validate_ticket} cas_validate_ticket */
async function validate_ticket(req, cas_validate_ticket) {
    const ticket = req.query.ticket;
    const service = cleanup_service_url(req.query.service); // we must simplify service URL before comparison & before sending to cas_server_validating_password (because it will be encoded => not ignored)
    if (req.query.pgtUrl && !is_service_matching(conf.proxy_cas_services, service)) {
        throw "service " + service + " is not allowed to ask proxy tickets. Allow it in conf.proxy_cas_services"
    }
    const ticket_info = await get_allowed_ticket(req.sessionStore, service, ticket);
    if (!ticket_info.v2_response) {
        console.log("proxying ticket", cas_validate_ticket.name, ticket);

        const v2_response = await cas_validate_ticket(service, ticket, ticket_info.addServiceHashtoPath, req.query.pgtUrl);
        if (v2_response.uid !== ticket_info.uid) {
            console.log("logged user has changed. Expected:", ticket_info.uid, "got", v2_response.uid)
            expire_session_uid(req.sessionStore, ticket_info.sessionID)
            throw "logged user has changed";
        }

        if (cas_validate_ticket.name.match(/v2/)) {
            ticket_info.v2_response = v2_response;
        }
    }
    return ticket_info;
}

// to remove with Express v5, see https://stackoverflow.com/a/38083802/3005203
const handle_error = (callback) => async (req, res, next) => {
    try {
        await callback(req, res, next)
    } catch (err) {
        console.error(err)
        res.send("err")
    }
}

const throw_ = e => { throw e }

/** @typedef {{ if_IP_in?: string[]}} req_allowed_conds */
/**
 * @param {req_allowed_conds} conds 
 * @param {string} cond_name
 */
const is_req_allowed_ = (req, conds, cond_name) => (
    conds.if_IP_in ? (
        conds.if_IP_in && require("ip-range-check")(req.ip, conds.if_IP_in)
    ) : throw_(`badly configured "${cond_name}"`)
)
/** 
 * @param {'allow_api_req' | 'allow_back_channel_single_logout'} cond_name
 */
const is_req_allowed = (req, cond_name) => (
    is_req_allowed_(req, conf[cond_name], cond_name)
)

function check_api_req_allowed(req) {
    if (!is_req_allowed(req, 'allow_api_req')) throw "API not allowed " + req.ip
}

/**
 * @param {Date} validated_otp 
 * @param {string} service 
 */
function is_validated_otp_too_old(validated_otp, service) {
    if (validated_otp) {
        const validity_seconds = Math.min(...conf.max_otp_validity_per_service.filter(e => h.is_service_matching(e, service)).map(e => e.validity_seconds))
        if (validity_seconds !== Infinity) {
            //console.log("is_validated_otp_too_old", service, "validated: ", new Date(validated_otp), "validity_seconds", validity_seconds)
            return Date.now() - +validated_otp > validity_seconds * 1000 && { validity_seconds }
        }
    }
    return false
}


function get_valid_uid(session) {
    if (session.uid && h.seconds_since(+session.validated_uid) > conf.uid_validity_seconds) {
        console.log("must check uid has not changed", session.uid, ": issued", session.validated_uid)
        return undefined
    }
    return session.uid
}

let last_attempts = {}
const throttle_time_window = 2 /*minutes*/ * 60
function may_throttle(uid) {
    let now = Date.now()
    let attempts = last_attempts[uid] ?? []
    // only keep recent attempts
    attempts = attempts.filter(d => now - d < throttle_time_window * 1000)
    // throttle X seconds for X recent attemps 
    const throttle = attempts.length > 2 ? attempts.length /* seconds */ : 0
    if (throttle) console.log('throttling', uid, throttle, "seconds")    
    last_attempts[uid] = [...attempts, now]
    return h.setTimeoutPromise(throttle * 1000)
}

function routing() {
    let router = express.Router();

    router.use(function (req, res, next) {
        if (req.query.service) {
            // weird comparison from Jasig/Apereo CAS (*) will not work after we encode app service.
            // => simplify what we can to avoid some issues (eg: shib-auth-cas uses a different "entityId" encoding at login and serviceValidate, when using option "shibcas.entityIdLocation=embed")
            // (*) it thinks http://host/?foo=bar&boo is same as http://host/?foo=bar%26boo , cf https://issues.jasig.org/browse/CAS-1438 https://github.com/apereo/cas/pull/419 https://github.com/apereo/cas/commit/3975dad468a48340d739d3056175973c188c76cb
            req.query.service = simplify_service_url(req.query.service)
        }
        // it seems Chrome may cache redirect if not told otherwise
        res.header('Cache-Control', 'private, no-cache, no-store');
        
        next()
    })

    router.get('/login*', handle_error(async function(req, res) {
        if (!req.session.cookie.originalMaxAge) {
            // increase validity, the default ttl is the one for saved tickets
            req.session.cookie.maxAge = conf.otp_validity_seconds * 1000
        }
    
        const ticket = req.query.ticket
        const service = req.query.service
        let consumed_ticket = false
        let details
        if (service && !is_service_allowed(service)) {
            h.my_log(req, "service is not allowed (cf conf.allowed_services)")
            return res.send("Application non autorisée à utiliser CAS")
        }
        if (!get_valid_uid(req.session)) {
            if (req.query.gateway) {
                return res.redirect(service) // no way
            } else if (!ticket) {
                return require_a_ticket(res, service);
            } else {
                try {
                    consumed_ticket = true
                    details = await get_logged_user_in_session(req, req.session, service, ticket, shouldAddServiceHashtoPath(req));
                } catch (err) {
                    console.error(err)
                    return res.send("erreur: " + err + html_remove_ticket_script)
                }
            }
        }

        try {
            if (req.query.ask == 'rememberMe') {
                rememberMe_page(res, ticket)
                return
            }
            const validated_otp_too_old = is_validated_otp_too_old(req.session.validated_otp, service)
            let no_need_otp = Boolean(req.session.validated_otp && !validated_otp_too_old) || await cond_no_otp.no_otp(req)
            if (no_need_otp === 'suggestActivatingOtp' && req.session.suggestActivatingOtp !== 'ignore') {
                req.session.suggestActivatingOtp = 'ignore'
                res.render('suggestActivatingOtp.ejs', { service })
            } else if (no_need_otp) {
                if (!ticket && 'auth_checked' in req.query) {
                    return res.redirect(service) // back from password CAS with no ticket => it must be CAS gateway
                }
                if (req.session.validated_otp && !details?.validated_otp_via_FC) {
                    h.my_log_if_ticket(req, "reusing validated OTP from session")
                }
                onLoginSuccess(req, res, ticket, consumed_ticket)
            } else if (req.query.gateway) {
                return res.redirect(service) // no way
            } else {
                h.my_log(req, "requiring OTP", validated_otp_too_old ? { validated_otp_too_old: true } : {})
                login_page(res, req.session.uid, ticket, h.getAndDelete(req.session, 'error'), { validated_otp_too_old });
            }
        } catch (err) {
            console.error(err)
            return res.send("erreur: " + err)
        }
    }))

    router.post('/login*', handle_error(function(req, res) {
        if (req.body.logoutRequest) {
            if (is_req_allowed(req, 'allow_back_channel_single_logout')) {
                if (is_service_allowed(req.query.service)) { // sanity check

                    const ticket = (req.body.logoutRequest.match(/SessionIndex>(.*?)</) || [])[1]
                    console.log("logoutRequest", ticket)
                    expire_session_uid_from_ticket(req.sessionStore, req.mongo_collection, ticket) // (done async)
                    
                    // proxy SLO to application
                    fetch(req.query.service, { method: 'POST', redirect: 'manual', body: new URLSearchParams(req.body) })
                        .catch(err => {
                            console.warn(`Unable to propagate SingleLogout to ${req.query.service} because of ${err}`);
                        });
                }
            } else {
                console.error("ignoring SingleLogout request from IP", req.ip, " since it is not allowed in conf.allow_back_channel_single_logout.if_IP_in")
            }
            res.send('')
        } else if (req.body.rememberMe && req.session.validated_otp) {
            req.session.long_term_otp = req.body.rememberMe !== 'skip'
            if (req.session.long_term_otp) {
                h.my_log(req, 'setting long_term_otp')
                // set cookie & session validity
                req.session.cookie.maxAge = conf.otp_long_term_validity_seconds * 1000
            }
            onLoginSuccess(req, res, req.body.ticket, true);
        } else if (req.body.token && req.session.uid) {
            const uid = req.session.uid
            may_throttle(uid).then(() => (
                verifyOtp(uid, req.body.token)
            )).then(method => {
                delete last_attempts[uid]
                set_validated_otp(req, method)
                res.redirect(ourUrl({ ...h.pick(req.query, 'service', 'renew'), ask: 'rememberMe', ticket: req.body.ticket }))
            }).catch(err => {
                login_page(res, uid, req.body.ticket, err, {})
            })
        } else {
            if (!req.session.uid) h.my_log(req, "weird expired session?")
            req.session.error = "La session avait expiré, veuillez recommencer" // ??
            res.redirect(ourUrl(h.pick(req.query, 'service', 'renew')))
        }
    }))
    
    router.get('/validate', handle_error(async function (req, res) {
        try {
            const ticket_info = await validate_ticket(req, casv1_validate_ticket);
            res.send("yes\n" + ticket_info.uid + "\n")
        } catch {
            res.send("no\n\n")
        }
    }))

    const serviceValidate = async function (req, res) {
        res.header('Content-Type', 'application/xml; charset=UTF-8')
        try {
            const ticket_info = await validate_ticket(req, casv2_validate_ticket);
            res.send(ticket_info.v2_response.raw_response)
        } catch (err) {
            if (err) console.error(err)
            res.send(validateErrorXml)
        }
    }
    router.get('/serviceValidate', handle_error(serviceValidate))
    router.get('/p3/serviceValidate', handle_error(serviceValidate))

    router.get('/proxyValidate', handle_error(async function (req, res) {
        if (req.query.ticket?.match(/^PT-/)) {
            // proxy unchanged request to cas_server_validating_password
            res.header('Content-Type', 'application/xml; charset=UTF-8')
            res.send(await (await fetchFromCas('/proxyValidate', req.query)).text())
        } else {
            await serviceValidate(req, res)
        }
    }))

    router.get('/proxy', handle_error(async function (req, res) {
        // proxy unchanged request to cas_server_validating_password
        res.header('Content-Type', 'application/xml; charset=UTF-8')
        res.send(await (await fetchFromCas('/proxy', req.query)).text())
    }))

    router.get('/logout', handle_error(async function (req, res) {
        h.my_log(req, "logout")
        req?.session?.destroy(_ => {})
        res.redirect(conf.cas_server_validating_password_base_url_public + '/logout?' + querystring.stringify(req.query))
    }))

    // logout all user sessions
    router.delete('/api/ssoSessions', handle_error(async function (req, res) {
        check_api_req_allowed(req)
        if (!req.query.username) throw "missing query param 'username' to logout"
        res.send(await req.mongo_collection.deleteMany({ "session.uid": req.query.username }))
    }))

    router.get('/log', (_req, res) => res.send(''))

    return router
}

module.exports = routing;
