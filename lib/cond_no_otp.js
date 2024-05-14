const fetch = require('node-fetch')
const h = require('./helpers')
const conf = require('../conf');

/** @typedef {{ if_IP_in?: string[], if?: (req) => Promise<boolean|'suggestActivatingOtp'>, if_service?: h.service_tests, if_not_service?: h.service_tests }} conds */

/** @template {conds} T 
  * @param {T} conds
  * @param {string} msg */
async function compute_no_otp_conds(req, conds, msg) {
    if (conds.if_IP_in) {
        if (require("ip-range-check")(req.ip, conds.if_IP_in)) {
            console.log(msg + " because of conds.if_IP_in")
            return true 
        }
    }
    if (conds.if) {
        const ret = await conds.if(req)
        if (ret) {
            console.log(msg + " because of conds.if " + (conds.if?.name !== 'if' && conds.if?.name || ''))
            return ret
        }
    }
    if (req.query.service) {
        if (conds.if_service) {
            if (h.is_service_matching(conds.if_service, req.query.service)) {
                console.log(msg + " because of conds.if_service for service", req.query.service)
                return true
            }
        }
        if (conds.if_not_service) {
            if (!h.is_service_matching(conds.if_not_service, req.query.service)) {
                console.log(msg + " because of conds.if_not_service for service", req.query.service)
                return true
            }
        }
    }
    return false
}

/** @param {string} uid */
async function otp_not_activated(uid) {
    const url = conf.api_url + '/users/'+ uid +'/' + h.get_hash(conf.api_users_secret, uid)
    const response = await fetch(url)
    if (response.ok) {
        const data = await response.json()
        if (data?.code === 'Ok') {
            const activated = Object.values(data.user.methods).some(e => e.active)
            return !activated
        }
    }
    throw "Problème technique, veuillez ré-essayer plus tard."
}    

async function no_otp(req) {
    let ret = await compute_no_otp_conds(req, conf.no_otp, req.ip + " " + req.session.uid + ' : no OTP')
    if (ret) {
        return ret
    }
    ret = await compute_no_otp_conds(req, conf.no_otp?.if_not_activated_for_user_and || {}, req.ip + " " + req.session.uid + ' : no OTP if not activated for user')
    if (ret) {
        if (await otp_not_activated(req.session.uid)) {
            console.log("no OTP for not activated user", req.session.uid, "and service", req.query.service, ret)
            return ret
        }
    }
    return false
}

module.exports = { no_otp }
