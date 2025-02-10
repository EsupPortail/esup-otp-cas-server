#!/usr/bin/env node

const fetch = require('node-fetch')
const conf = require('./conf');
const { compute_no_otp_conds } = require('./lib/cond_no_otp');
const { my_log_if_ticket, my_log } = require('./lib/helpers');

async function test_otp_needed(service, uid, activated) {
    const req = { query: { service }, session: { uid }, get() { return "" } }
    let ret = await compute_no_otp_conds(req, conf.no_otp)
    if (ret) {
        my_log(req, 'no OTP', { reason: ret.reason })
        return ret.ret
    }
    ret = await compute_no_otp_conds(req, conf.no_otp?.if_not_activated_for_user_and || {})
    if (ret) {
        if (!activated) {
            if (req.session.suggestActivatingOtp !== 'ignore' && ret.ret === 'suggestActivatingOtp') {
                my_log(req, "no OTP for not activated user (suggestActivatingOtp) ", { reason: ret.reason })
            } else {
                my_log(req, "no OTP for not activated user ", { reason: ret.reason })
            }
            return ret.ret
        } else {
            my_log(req, `OTP since activated`, { reason: ret.reason })
        }
    } else {
        my_log(req, `OTP required`)
    }
}

function usage() {
    console.log("./cli.js test_otp_needed <service> <uid> <is otp currently activated>")
    process.exit(1)
}

const [,,cmd, ...args] = process.argv
if (cmd === 'test_otp_needed') {
    if (args.length !== 3) usage()
    test_otp_needed(...args).catch(err => console.error(err))
} else {
    console.error(`unknown cmd ${cmd}`)
    usage()
}
