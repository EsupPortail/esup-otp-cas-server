const crypto = require('crypto');

const conf = require('../conf')


/** @param {number} date */
const seconds_since = (date) => (Date.now() - date) / 1000

function raw_hash(algo, data) {
    const hash = crypto.createHash(algo);
    hash.update(data)
    return hash.digest('hex')
}

/** @param {String} uid */
function get_hash(uid) {
    const d = new Date();
    const present_salt = d.getUTCDate()+d.getUTCHours().toString();
    //console.log("present-salt for", uid, ":", present_salt);
    return raw_hash('SHA256', raw_hash('MD5', conf.api_users_secret) + uid+present_salt);  
}

/** @type {<T extends object, K extends keyof T>(object: T, key: K) => T[K]} */
function getAndDelete(o, key) {
    const val = o[key]
    delete o[key]
    // @ts-ignore
    return val
}

/** @type {<T extends object, K extends keyof T>(object: T, ...paths: Array<K>) => Pick<T, K>} */
function pick(o, ...keys) {
    let r = {}
    for (const key of keys) {
        // @ts-ignore
        if (o[key]) r[key] = o[key]
    }
    // @ts-ignore
    return r
}

/** @param {string[]} domains_and_hostnames
  * @param {string} hostname */
 const matches_domains_and_hostnames = (domains_and_hostnames, hostname) => (
    domains_and_hostnames.some(domain_or_hostname => (
        hostname === domain_or_hostname || hostname.endsWith("." + domain_or_hostname)
    ))
)

/** @typedef {{ regexp?: string, domains_and_hostnames?: string[] }} service_tests */

/** @param {service_tests} service_tests
  * @param {string} service */
const is_service_matching = (service_tests, service) => (
    service_tests.regexp && service.match(service_tests.regexp) ||
    service_tests.domains_and_hostnames && matches_domains_and_hostnames(service_tests.domains_and_hostnames, new URL(service).hostname)
)

function decodeEntities(encodedString) {
    const translate_re = /&(apos|quot|amp|lt|gt);/g;
    const translate = { apos: "'", quot: '"', amp : "&", lt  : "<", gt  : ">" };
    return encodedString
        .replace(translate_re, (_, entity) => (
            translate[entity]
        )).replace(/&#(\d+);/gi, (_, numStr) => (
            String.fromCharCode(parseInt(numStr, 10)) // needed for XML?
        ));
}

module.exports = { seconds_since, get_hash, getAndDelete, pick, is_service_matching, decodeEntities }
