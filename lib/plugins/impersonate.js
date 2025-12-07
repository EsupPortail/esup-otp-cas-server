const conf = require('../../conf')
const { hooks } = require("../cas_server")

async function allowImpersonate(service, user) {
    const url = conf.plugins.impersonate.canImpersonateUrl + "?uid=" + encodeURIComponent(user) + "&service=" + encodeURIComponent(service)
    try {
        const resp = await fetch(url)
        return resp.status === 200;
    } catch (err) {
        console.error("error fetch url", url, ":", err)
        return false;
    }
}

hooks.before_save_allowed_ticket.push((req, ticket_info) => {
    const m = req.header('cookie')?.match(`${conf.plugins.impersonate.cookieName}=([^;]*)`)
    if (m) {
        // @ts-expect-error
        ticket_info.wantedUserId = m[1]
    }
})
hooks.after_validate_ticket.push(async (req, ticket_info, ticket, service) => {
    if ("wantedUserId" in ticket_info) {
        const { wantedUserId } = ticket_info
        const realUserId = ticket_info.uid
        console.log("verifying impersonate", realUserId, '=>', wantedUserId, "for service", service, "for ticket", ticket);
        if (await allowImpersonate(req.query.service, realUserId)) {
            console.log("allowing impersonate", realUserId, '=>', wantedUserId, "for service", service, "for ticket", ticket);
            // @ts-expect-error
            ticket_info.uid = wantedUserId
            if (ticket_info.v2_response) {
                ticket_info.v2_response.raw_response = ticket_info.v2_response.raw_response.replace("<cas:user>" + realUserId + "</cas:user>", "<cas:user>" + wantedUserId + "</cas:user>")
            }
        }
    }
})
