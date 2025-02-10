const fetch = require('node-fetch')
const h = require('./helpers')
const conf = require('../conf');

/** @typedef {{ if_IP_in?: string[], if?: (req) => Promise<boolean|'suggestActivatingOtp'>, if_any?: ((req) => Promise<boolean|'suggestActivatingOtp'>)[], if_service?: h.service_tests, if_not_service?: h.service_tests }} conds */

/** @template {conds} T 
  * @param {T} conds
  * @returns {Promise<false | { ret: true|'suggestActivatingOtp', reason: string }>} */
async function compute_no_otp_conds(req, conds) {
    if (conds.if_IP_in) {
        if (require("ip-range-check")(req.ip, conds.if_IP_in)) {
            return { ret: true, reason: "conds.if_IP_in"} 
        }
    }
    if (conds.if) {
        const ret = await conds.if(req)
        if (ret) {
            return { ret, reason: "conds.if " + (conds.if?.name !== 'if' && conds.if?.name || '') }
        }
    }
    if (conds.if_any) {
        for (const one of conds.if_any) {
            const ret = await one(req)
            if (ret) {
                return { ret, reason: "conds.if_any " + (one?.name !== 'if' && one?.name || '') }
            }
        }
    }
    if (req.query.service) {
        if (conds.if_service) {
            if (h.is_service_matching(conds.if_service, req.query.service)) {
                return { ret: true, reason: "conds.if_service" }
            }
        }
        if (conds.if_not_service) {
            if (!h.is_service_matching(conds.if_not_service, req.query.service)) {
                return { ret: true, reason: "conds.if_not_service" }
            }
        }
    }
    return false
}

/** @param {string} uid */
async function otp_not_activated(uid) {
    const url = conf.api_url_internal + '/users/'+ uid +'/' + h.get_hash(conf.api_users_secret, uid)
    const response = await fetch(url)
    if (response.ok) {
        const data = await response.json()
        if (data?.code === 'Ok') {
            const activated = Object.values(data.user.methods).some(e => e.active)
            return !activated
        }
        console.error("checking otp_not_activated failed. esup-otp-api responded", data)
    } else {
        console.error("checking otp_not_activated failed. esup-otp-api responded HTTP", response.status)
    }
    throw "Problème technique, veuillez ré-essayer plus tard."
}    

async function no_otp(req) {
    let ret = await compute_no_otp_conds(req, conf.no_otp)
    if (ret) {
        h.my_log_if_ticket(req, 'no OTP', { reason: ret.reason })
        return ret.ret
    }
    ret = await compute_no_otp_conds(req, conf.no_otp?.if_not_activated_for_user_and || {})
    if (ret) {
        if (await otp_not_activated(req.session.uid)) {
            if (req.session.suggestActivatingOtp !== 'ignore' && ret.ret === 'suggestActivatingOtp') {
                h.my_log(req, "no OTP for not activated user (suggestActivatingOtp) ", { reason: ret.reason })
            } else {
                h.my_log_if_ticket(req, "no OTP for not activated user ", { reason: ret.reason })
            }
            return ret.ret
        } else {
            h.my_log(req, `OTP since activated`, { reason: ret.reason })
        }
    }
    return false
}

module.exports = { no_otp, compute_no_otp_conds }
