module.exports = {
    our_base_url: "https://cas.univ.fr/mfa",
    cas_server_validating_password_base_url_public: "https://cas.univ.fr/cas",
    cas_server_validating_password_base_url_internal: "https://cas.univ.fr/cas",
    
    allowed_services: {
        domains_and_hostnames: [ "univ.fr" ],
        regexp: undefined,
    },
    proxy_cas_services: {
        //domains_and_hostnames: [],
        //regexp: ...
    },

    no_otp: {
        //if_IP_in: "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16".split(" "),
        //if_service: { regexp: '^https://foo[.]univ[.]fr/' },
        //if_not_service: { regexp: '^https://bar[.]univ[.]fr/' },
        if_not_activated_for_user_and: {
            //if_IP_in: "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16".split(" "),
            //if_service: { regexp: '^https://foo[.]univ[.]fr/' },
            //if_not_service: { regexp: '^https://bar[.]univ[.]fr/' },
        },
    },

    max_otp_validity_per_service: [
        {
            validity_seconds: 15 /*minutes*/ * 60,
            domains_and_hostnames: ['otpmanager.univ.fr'],
        },
    ],
    
    api_url: "http://localhost:3000/",
    api_password: "changeit",
    api_users_secret: "changeit",
    
    ticket_validity_seconds: 10, // same as Apereo CAS "cas.ticket.st.time-to-kill-in-seconds"
    uid_validity_seconds: 30 /*minutes*/ * 60,
    otp_validity_seconds: 30 /*minutes*/ * 60,
    otp_long_term_validity_seconds: 30 /*days*/ * 24 * 60 * 60,

    //trust_proxy: 'loopback', // http://expressjs.com/en/guide/behind-proxies.html

    allow_back_channel_single_logout: {
        if_IP_in: [],
    },

    allow_api_req: {
        if_IP_in: [ '::1' ], // localhost
    },

    session_store: {
        mongoUrl: 'mongodb://owner:xxx@localhost/esup-otp-cas-server',
        options: {
            secret: 'changeit' // NB: express-session sends session ID signed with this secret => something even harder to randomly guess...
        }
    },
}
