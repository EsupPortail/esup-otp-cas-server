const querystring = require('querystring')
const express = require('express');
const fetch = require('node-fetch')

const cond_no_otp = require('./cond_no_otp')
const h = require('./helpers')
const conf = require('../conf')

/** @typedef {{ uid: string, raw_response: string }} v2_response */
/** @typedef {{ uid: string, service: string, v2_response?: v2_response, date: number }} ticket_info */

/** @typedef {{}} empty_session */
/** @typedef {{ uid: string, ticket_to_v2_response: Object.<string, v2_response> }} session_but_not_validated (ticket consumed) */
/** @typedef {{ uid: string, validated_otp: number, long_term_otp: boolean }} session_validated */



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

/** @param {{ service: string, renew?: string, ask?: string, ticket?: string, pgtUrl?: string }} query */
const ourUrl = (query) => (
    conf.our_base_url + '/login?' + querystring.stringify(query)
)


/** @param {string} uid
  * @param {string} otp
  * @returns {Promise<void>} */
async function verifyOtp(uid, otp) {
    console.log('verifyOtp', uid, otp)
    const response = await fetch(conf.api_url + 'protected/users/' + uid + '/' + otp + '/', {
        method: 'POST',
        headers: { Authorization: "Bearer " + conf.api_password },
    })
    if (response.ok) {
        const infos = await response.json()
        if (infos && infos.code === 'Ok') return
        if (infos && infos.code === 'Error') throw "Le code est invalide."
    }
    throw "Probl??me technique, veuillez r??-essayer plus tard."
}

/** @param {string} service
  * @param {string} ticket
  * @returns {Promise<{ uid: string, raw_response: string}>} */
async function casv1_validate_ticket(service, ticket) {
    const params = { service: ourUrl({ service }) + '&auth_checked', ticket }
    const url = conf.cas_server_validating_password_base_url + '/validate?' + querystring.stringify(params)
    const response = await fetch(url)
    if (response.ok) {
        const body = await response.text();
        const [l1, l2] = body.split("\n")
        if (l1 === 'yes') return { uid: l2, raw_response: body }
        if (l2 === 'no') throw { msg: "error" }
    }
    throw { msg: "Probl??me technique, veuillez r??-essayer plus tard." }
}
/** @param {string} service
  * @param {string} ticket
  * @param {string=} pgtUrl
  * @returns {Promise<v2_response>} */
async function casv2_validate_ticket(service, ticket, pgtUrl) {
    const params = { service: ourUrl({ service }) + '&auth_checked', ticket, pgtUrl }
    const url = conf.cas_server_validating_password_base_url + '/serviceValidate?' + querystring.stringify(params)
    const response = await fetch(url)
    if (response.ok) {
        const body = await response.text();
        const m = body.match(/<cas:authenticationSuccess>/) && body.match(/<cas:user>(.*?)<\/cas:user>/)
        if (m) return { uid: m[1], raw_response: body }
        const err = body.match(/<cas:authenticationFailure code="(.*)">(.*?)</)
        if (err) throw { code: err[1], msg: err[2], raw_response: body }
    }
    throw { msg: "Probl??me technique, veuillez r??-essayer plus tard." }
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

/** @param {string} service
  * @param {string} ticket
  * @returns {Promise<ticket_info>} */
const get_allowed_ticket = (sessionStore, service, ticket) => (
    new Promise((resolve, reject) => {
        sessionStore.get(ticket, (err, info) => {
            if (err) {
                console.error(err)
                return reject()
            }
            sessionStore.destroy(ticket) // only once
            if (!info) {
                console.error("unknown ticket", ticket, "(already validated?)")
            } else if (info.service !== service) {
                console.error("invalid service: at login= ", info.service, "  at validate= ", service)
            } else if (h.seconds_since(info.date) > conf.ticket_validity_seconds) {
                console.error("ticket expired", ticket, ": issued", h.seconds_since(info.date), "seconds ago")
            } else {
                console.log("ticket", ticket, "is valid for uid", info.uid)
                return resolve(info)
            }
            reject()
        })
    })
)

/** @param {session_but_not_validated} session
  * @param {string} service
  * @param {string} ticket */
async function get_logged_user_in_session(session, service, ticket) {
    const v2_response = await casv2_validate_ticket(service, ticket);
    console.log("used ticket", ticket, "to know the logged user. Saving ticket and response ");
    session.uid = v2_response.uid;
    if (is_service_matching(conf.proxy_cas_services, service)) {
        // we can not reuse the response since it was done *without* the app pgtUrl
    } else {
        if (!session.ticket_to_v2_response)
            session.ticket_to_v2_response = {};
        session.ticket_to_v2_response[ticket] = v2_response
    }
}

/** @param {string} uid
  * @param {string} ticket
  * @param {string=} error */
function login_page(res, uid, ticket, error) {
    res.render('login.ejs', {
        error,
        ticket,
        params: {
            apiUrl: conf.api_url,
            uid,
            userHash: h.get_hash(uid),
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
    const redirectURL = conf.cas_server_validating_password_base_url + '/login?service=' + encodeURIComponent(ourUrl({ service }) + '&auth_checked') + (gateway ? '&gateway=true' : '');
    res.redirect(redirectURL);
}

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
        console.log("there was parallel logins. ticket", ticket, "is forgotten, will require a new one")
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
    }
    save_allowed_ticket(req.sessionStore, ticket, ticket_info);

    if (service) {
        res.redirect(service + (service.includes("?") ? "&" : "?") + "ticket=" + encodeURIComponent(ticket));
    } else {
        res.send("Utilisateur correctement authentifi??");
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
        const v2_response = await cas_validate_ticket(service, ticket, req.query.pgtUrl);
        if (v2_response.uid !== ticket_info.uid)
            throw "weird...";
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

function routing() {
    let router = express.Router();

    router.use(function (req, res, next) {
        if (req.query.service) {
            // weird comparison from Jasig/Apereo CAS (*) will not work after we encode app service.
            // => simplify what we can to avoid some issues (eg: shib-auth-cas uses a different "entityId" encoding at login and serviceValidate, when using option "shibcas.entityIdLocation")
            // (*) it thinks http://host/?foo=bar&boo is same as http://host/?foo=bar%26boo , cf https://issues.jasig.org/browse/CAS-1438 https://github.com/apereo/cas/pull/419 https://github.com/apereo/cas/commit/3975dad468a48340d739d3056175973c188c76cb
            req.query.service = simplify_service_url(req.query.service)
        }
        next()
    })

    router.get('/login', handle_error(async function(req, res) {
        if (!req.session.cookie.originalMaxAge) {
            // increase validity, the default ttl is the one for saved tickets
            req.session.cookie.maxAge = conf.otp_validity_seconds * 1000
        }
    
        const ticket = req.query.ticket
        const service = req.query.service
        let consumed_ticket = false
        if (service && !is_service_allowed(service)) {
            console.error(service, "is not allowed (cf conf.allowed_services)")
            return res.send("Application non autoris??e ?? utiliser CAS")
        }
        if (!req.session.uid) {
            if (req.query.gateway) {
                return res.redirect(service) // no way
            } else if (!ticket) {
                return require_a_ticket(res, service);
            } else {
                try {
                    consumed_ticket = true
                    await get_logged_user_in_session(req.session, service, ticket);
                } catch (err) {
                    console.error(err)
                    return res.send("erreur: " + err + html_remove_ticket_script)
                }
            }
        }

        try {
            if (req.query.ask == 'rememberMe') {
                rememberMe_page(res, ticket)
            } else if (req.session.validated_otp || await cond_no_otp.no_otp(req)) {
                if (!ticket && 'auth_checked' in req.query) {
                    return res.redirect(service) // back from password CAS with no ticket => it must be CAS gateway
                }
                onLoginSuccess(req, res, ticket, consumed_ticket)
            } else if (req.query.gateway) {
                return res.redirect(service) // no way
            } else {
                console.log("requiring OTP for user", req.session.uid, "and service", service)
                login_page(res, req.session.uid, ticket, h.getAndDelete(req.session, 'error'));
            }
        } catch (err) {
            console.error(err)
            return res.send("erreur: " + err)
        }
    }))

    router.post('/login', handle_error(function(req, res) {
        if (req.body.logoutRequest) {
            if (require("ip-range-check")(req.ip, conf.allow_back_channel_single_logout.if_IP_in)) {
                if (is_service_allowed(req.query.service)) { // sanity check
                    // proxy SLO to application
                    fetch(req.query.service, { method: 'POST', body: new URLSearchParams(req.body) })
                }
            } else {
                console.error("ignoring SingleLogout request from IP", req.ip, " since it is not allowed in conf.allow_back_channel_single_logout.if_IP_in")
            }
            res.send('')
        } else if (req.body.rememberMe && req.session.validated_otp) {
            req.session.long_term_otp = req.body.rememberMe !== 'skip'
            if (req.session.long_term_otp) {
                // set cookie & session validity
                req.session.cookie.maxAge = conf.otp_long_term_validity_seconds * 1000
            }
            onLoginSuccess(req, res, req.body.ticket, true);
        } else if (req.body.token) {
            const uid = req.session.uid
            verifyOtp(uid, req.body.token).then(() => {
                req.session.validated_otp = Date.now()
                // will set session storage validity
                req.session.cookie.maxAge = conf.otp_validity_seconds * 1000

                res.redirect(ourUrl({ ...h.pick(req.query, 'service', 'renew'), ask: 'rememberMe', ticket: req.body.ticket }))
            }).catch(err => login_page(res, uid, req.body.ticket, err))
        } else {
            req.session.error = "La session avait expir??, veuillez recommencer" // ??
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

    router.get('/proxyValidate', handle_error(async function (req, res) {
        if (req.query.ticket?.match(/^PT-/)) {
            // proxy unchanged request to cas_server_validating_password
            res.header('Content-Type', 'application/xml; charset=UTF-8')
            const url = conf.cas_server_validating_password_base_url + '/proxyValidate?' + querystring.stringify(req.query)
            res.send(await (await fetch(url)).text())
        } else {
            await serviceValidate(req, res)
        }
    }))

    router.get('/proxy', handle_error(async function (req, res) {
        // proxy unchanged request to cas_server_validating_password
        res.header('Content-Type', 'application/xml; charset=UTF-8')
        const url = conf.cas_server_validating_password_base_url + '/proxy?' + querystring.stringify(req.query)
        res.send(await (await fetch(url)).text())
    }))

    return router
}

module.exports = routing;
