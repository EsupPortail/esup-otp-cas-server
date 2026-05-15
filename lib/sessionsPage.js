import parse_user_agent from 'parse-user-agent';

import { fetchFromCas, ourUrl, lookupGeolocation } from './cas_server.js';
import conf from "../conf.js";
import * as h from "./helpers.js"

export const path = "sessions";
export const URL = `${conf.our_base_url}/${path}`;

export async function display(req, res) {
    if (!req.session.uid) {
        return res.redirect(ourUrl({ service: URL }))
    }
    const apereoCasSessions = await getApereoCasSessionsForUser(req.session.uid);

    /**
     * @type { OtpSession[] }
     */
    const otpSessions = await req.mongo_collection.find({ "session.uid": req.session.uid, "session.cookie": { $exists: true } }).toArray();

    const sessions = groupSessionsByST(apereoCasSessions, otpSessions);

    const sessionsInfos = await Promise.all(sessions.map(extractInfosFromSession));
    const currentSession = sessionsInfos.find(session => session.ST == req.session.ticket_for_SLO);
    if (currentSession) {
        currentSession.currentSession = true;
    }

    sessionsInfos.sort((a, b) => (b.lastUseDate?.getTime() || 0) - (a.lastUseDate?.getTime() || 0));

    res.render('sessions.ejs', { sessions: sessionsInfos, path });
}

/**
 * @param { ApereoSession[] } apereoCasSessions
 * @param { OtpSession[] } otpSessions
 * @returns { { otpSession: ?OtpSession, apereoCasSession: ?ApereoSession }[] }
 */
function groupSessionsByST(apereoCasSessions, otpSessions) {
    /**
     * @type { Map<string, ApereoSession> }
     */
    const apereoCasSessionByST = new Map();
    apereoCasSessions.forEach(apereoCasSession => {
        getSTs(apereoCasSession).forEach(ST => {
            apereoCasSessionByST.set(ST, apereoCasSession);
        })
    })

    /**
     * @type { { otpSession: ?OtpSession, apereoCasSession: ?ApereoSession }[] }
     */
    const sessions = [];
    otpSessions.forEach(otpSession => {
        const apereoCasSession = apereoCasSessionByST.get(otpSession.session.ticket_for_SLO);
        if (apereoCasSession) {
            apereoCasSession.merged = true;
        }
        sessions.push({ otpSession, apereoCasSession });
    })

    apereoCasSessions.filter(apereoCasSession => !apereoCasSession.merged)
        .forEach(apereoCasSession => {
            sessions.push({ apereoCasSession });
        })

    return sessions;
}

/**
 * @param {ApereoSession} apereoCasSession
 * @returns {string[]}
 */
function getSTs(apereoCasSession) {
    return Object.keys(apereoCasSession.authenticated_services);
}

/**
 * @param {Object} session
 * @param {?OtpSession} session.otpSession
 * @param {?ApereoSession} session.apereoCasSession
 * @returns {Promise<{
 *   ip: string,
 *   geolocation: ?{
 *     region: ?string,
 *     city: ?string,
 *   },
 *   userAgent: ?string,
 *   browser: string,
 *   loginDate: ?Date,
 *   lastUseDate: ?Date,
 *   mfaMethod: string,
 *   ST: string,
 *   TGT_hash: string, // only if no ST
 *   isOtpSession: boolean,
 *   isApereoSession: boolean,
 * }>}
 */
async function extractInfosFromSession({ otpSession, apereoCasSession }) {
    const ip = otpSession?.session.ip || apereoCasSession?.authentication_attributes.clientIpAddress;
    const geolocation = ip && await lookupGeolocation(ip);
    const userAgent = otpSession?.session.userAgent || apereoCasSession?.authentication_attributes.userAgent[0];
    const browser = userAgent && parse_user_agent(userAgent)?.clean_ua;
    const loginDate = h.olderDate([otpSession?.session.validated_uid, otpSession?.session.validated_otp, apereoCasSession?.authentication_date]);
    const lastUseDate = h.newerDate([otpSession?.session.lastUseDate, apereoCasSession?.last_used_date]);
    const ST = otpSession?.session.ticket_for_SLO || (apereoCasSession?.authenticated_services) && Object.keys(apereoCasSession?.authenticated_services)[0];
    const TGT_hash = !ST && apereoCasSession?.ticket_granting_ticket && h.sha256(apereoCasSession?.ticket_granting_ticket);
    return {
        ip: ip || null,
        geolocation: geolocation || null,
        userAgent: userAgent || "",
        browser: browser || null,
        loginDate: loginDate,
        lastUseDate: lastUseDate,
        mfaMethod: otpSession?.session.validated_method || "",
        ST: ST || "",
        TGT_hash: TGT_hash || "",
        isOtpSession: Boolean(otpSession),
        isApereoSession: Boolean(apereoCasSession),
    }
}

/**
 * @param {string} uid
 * @param {import("mongodb").Collection} mongo_collection
 * @param {Object} ticket
 * @param {?string} ticket.ST
 * @param {?string} ticket.TGT_hash
 */
export async function logout(uid, mongo_collection, { ST, TGT_hash }) {
    if (ST) {
        await logoutApereoSessionForUser(uid, session => getSTs(session).some(apereoST => apereoST == ST));
        await mongo_collection.deleteOne({ "session.uid": uid, "session.ticket_for_SLO": ST });
    } else if (TGT_hash) {
        await logoutApereoSessionForUser(uid, session => h.sha256(session.ticket_granting_ticket) == TGT_hash);
    }
}

/**
 * @param {String} principal
 * @returns {Promise<{
 *   totalSsoSessions: number // e.g. 28
 *   activeSsoSessions: ApereoSession[],
 * }>}
 */
async function getApereoCasSessionsForPrincipal(principal) {
    const res = await fetchFromCas(`/actuator/ssoSessions/users/${principal}`);
    const json = await res.json();
    json.ApereoSession ||= [];
    return json;
}

/**
 * @param {String} uid
 * @returns {Promise<ApereoSession[]>}
 */
async function getApereoCasSessionsForUser(uid) {
    const apereoCasSessions = (await getApereoCasSessionsForPrincipal(uid)).activeSsoSessions;
    // TODO rendre ça configurable via conf.js ?
    apereoCasSessions.push(...(await getApereoCasSessionsForPrincipal(`${uid}@UNIV-PARIS1.FR`)).activeSsoSessions);
    return apereoCasSessions;
}

/**
 * @param {string} uid
 * @param {(apereoSession: ApereoSession) => boolean} tgtFilter
 */
async function logoutApereoSessionForUser(uid, tgtFilter) {
    const TGT = (await getApereoCasSessionsForUser(uid))
        .find(tgtFilter)
        ?.ticket_granting_ticket;
    if (TGT) {
        await logoutApereoSession(TGT);
    }
}

/** @param {string} TGT  */
function logoutApereoSession(TGT) {
    return fetchFromCas(`/actuator/ssoSessions/${TGT}`, {}, { method: "DELETE" });
}

/**
 * @import { session_but_not_validated, session_validated } from './cas_server.js'
 * @typedef { Object } OtpSession
 * @property { session_but_not_validated & session_validated } session
 * @property { Date } expires 
 */

/**
 * @typedef { Object } ApereoSession
 * @property { String } authenticated_principal         e.g. "fnari"
 * @property { String } authentication_date             e.g. "2026-05-15T08:01:24.125204331Z"
 * @property { String } authentication_date_formatted   e.g. "2026-05-15T10:01:24Z"
 * @property { String } creation_date_formatted         e.g. "2026-05-15T10:01:24Z"
 * @property { String } last_used_date                  e.g. "2026-05-15T08:01:24.125204331Z"
 * @property { String } last_used_date_formatted        e.g. "2026-05-15T10:01:24Z"
 * @property { number } number_of_uses                  e.g. 0
 * @property { String } ticket_granting_ticket         e.g. "TGT-1-7nwePJSLoCeCef7KfLJQubwvHSrpm0pQHSG1fYUv-MtzHP8gY-byfWn4z1RHJ7C0C3g-cas-test2"
 * @property { Object } principal_attributes
 * @property { ApereoAuthenticationAttributes } authentication_attributes
 * @property { ApereoExpirationPolicy } expiration_policy
 * @property { boolean } remember_me                    e.g. false
 * @property { boolean } is_proxied                     e.g. false
 * @property { { [ST: String]: ApereoST } } authenticated_services
 * @property {? boolean } merged                        defined and used by esup-otp-cas-server
 * 
 * @typedef { Object } ApereoAuthenticationAttributes
 * @property {? String[] } org.apereo.cas.authentication.principal.REMEMBER_ME  only if remember-me, e.g. ["true"]
 * @property { String } credentialType                                          e.g. "RememberMeUsernamePasswordCredential"
 * @property { String } clientIpAddress                                         e.g. "172.20.11.240"
 * @property { String[] } samlAuthenticationStatementAuthMethod                 e.g. ["urn:oasis:names:tc:SAML:1.0:am:unspecified"]
 * @property { number[] } authenticationDate                                    e.g. [1778832081]
 * @property { String[] } authenticationMethod                                  e.g. ["LdapAuthenticationHandler"]
 * @property { String[] } successfulAuthenticationHandlers                      e.g. ["LdapAuthenticationHandler"]
 * @property { String[] } serverIpAddress                                       e.g. ["0:0:0:0:0:0:0:1"],
 * @property { String[] } userAgent                                             e.g. ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0"]
 * 
 * @typedef { Object } ApereoExpirationPolicy
 * @property { number } timeToIdle          e.g. 0
 * @property {? String } idleExpirationTime only if NOT remember-me, e.g. "2026-05-15T18:23:19.525571323Z"
 * @property { number } timeToLive          e.g. 7776000
 * @property { String } clock               e.g. "SystemClock[Z]"
 * @property { String } name                e.g. "RememberMeDelegatingExpirationPolicy-b1f097ea-d396-49d9-a3dd-982f189d11e3"
 * @property { String } maxExpirationTime   e.g. "2026-08-13T11:42:28.773749094Z"
 * 
 * @typedef { Object } ApereoST
 * @property { String } id          e.g. "https://ent.univ-paris1.fr/"
 * @property { String } originalUrl e.g. "https://ent.univ-paris1.fr/"
 * @property { String } principal   e.g. "fnari"
 * @property { String } source      e.g. "service"
 * @property { String } format      e.g. "XML"
 */
