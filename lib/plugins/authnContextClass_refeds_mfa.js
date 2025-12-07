const { hooks } = require("../cas_server")

hooks.after_validate_ticket.push(async (_req, ticket_info, _ticket, _service) => {
    if (ticket_info.validated_otp && ticket_info.v2_response) {
        let xml = ticket_info.v2_response.raw_response
        ticket_info.v2_response.raw_response = xml.replace('<cas:attributes>', '<cas:attributes>\n    <cas:authnContextClass>https://refeds.org/profile/mfa</cas:authnContextClass>')
    }
})
