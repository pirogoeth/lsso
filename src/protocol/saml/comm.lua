--
-- saml/comm.lua -- module that handles SAML communication
--

module('protocol.saml.comm', package.seeall)

-- Lua standard and external library imports
local os = require "os"
local xml = require "xml"

-- Internal library imports
local session = require "session"
local util = require "util"

-- SAML protocol constants
SAML_PROTO = {
    V2_0                         = "urn:oasis:names:tc:SAML:2.0:protocol",
    V1_1                         = "urn:oasis:names:tc:SAML:1.1:protocol",
    V1_0                         = "urn:oasis:names:tc:SAML:1.0:protocol",
}

SAML_STATUS = {
    SUCCESS                      = "urn:oasis:names:tc:SAML:2.0:status:Success",
    REQUESTER                    = "urn:oasis:names:tc:SAML:2.0:status:Requester",
    RESPONDER                    = "urn:oasis:names:tc:SAML:2.0:status:Responder",
    VERSION_MISMATCH             = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
    AUTHN_FAILED                 = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
    INVALID_ATTR_NAME_VALUE      = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
    INVALID_NAMEID_POLICY        = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
    NO_AUTHN_CONTEXT             = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
    NO_AVAIL_IDP                 = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
    NO_SUPPORTED_IDP             = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
    PARTIAL_LOGOUT               = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
    PROXY_COUNT_EXCESS           = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
    REQ_DENIED                   = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
    REQ_UNSUPPORTED              = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
    REQ_VERSION_DEPRECATED       = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated",
    REQ_VERSION_TOO_HIGH         = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh",
    REQ_VERSION_TOO_LOW          = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
    RESOURCE_UNKNOWN             = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized",
    TOO_MANY_RESPONSES           = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
    UNKNOWN_ATTR_PROFILE         = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile",
    UNKNOWN_PRINCIPAL            = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
    UNSUPPORTED_BINDING          = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding",
}

SAML_NAMEID = {
    TRANSIENT                    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    PERSISTENT                   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    ENTITY                       = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
    X509_SUBJECT                 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
    EMAIL_ADDR                   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    UNSPECIFIED                  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
}

SAML_CM = {
    BEARER                       = "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    H_O_K                        = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    SENDER_VOUCHES               = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches",
}

SAML_AUTHN_CTX_REF = {
    PASSWORD                     = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
}

SAML_ATTR_NAME_FMT = {
    BASIC                        = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
}

-- SAML protocol responses
function create_saml_response()
    local res = {
        xml = "samlp:Response",
        ["xmlns:samlp"]  = SAML_PROTO.V2_0,
        ["xmlns:saml"]   = "urn:oasis:names:tc:SAML:2.0:assertion",
        ["ID"]           = nil,
        ["Version"]      = "2.0",
        ["IssueInstant"] = nil,
        ["Destination"]  = nil,
        ["InResponseTo"] = nil,
        {
            xml = "saml:Issuer",
            nil,
        },
        {
            xml          = "samlp:Status",
            {
                xml      = "samlp:StatusCode",
                nil,
            },
        },
    }

    local res_id = "_" .. util.generate_random_string(32)

    res.ID = res_id
    res.IssueInstant = util.utc_time()

    return res
end

function create_authn_response()
    local ck = {
        xml              = "saml:Assertion",
        ["xmlns:xsi"]    = "http://www.w3.org/2001/XMLSchema-instance",
        ["xmlns:xs"]     = "http://www.w3.org/2001/XMLSchema",
        ["ID"]           = nil,
        ["Version"]      = "2.0",
        ["IssueInstant"] = nil,
        {
            xml = "saml:Issuer",
            nil,
        },
        {
            xml = "saml:Subject",
            {
                xml                 = "saml:NameID",
                ["SPNameQualifier"] = nil,
                ["Format"]          = SAML_NAMEID.TRANSIENT,
            },
            {
                xml        = "saml:SubjectConfirmation",
                ["Method"] = SAML_CM.BEARER,
                {
                    xml              = "saml:SubjectConfirmationData",
                    ["NotOnOrAfter"] = nil,
                    ["Recipient"]    = nil,
                    ["InResponseTo"] = nil,
                },
            },
        },
        {
            xml              = "saml:Conditions",
            ["NotBefore"]    = nil,
            ["NotOnOrAfter"] = nil,
            {
                xml = "saml:AudienceRestriction",
                {
                    xml = "saml:Audience",
                    nil,
                },
            },
        },
        {
            xml                     = "saml:AuthnStatement",
            ["AuthnInstant"]        = nil,
            ["SessionNotOnOrAfter"] = nil,
            ["SessionIndex"]        = nil,
            {
                xml = "saml:AuthnContext",
                {
                    xml = "saml:AuthnContextClassRef",
                    SAML_AUTHN_CTX_REF.PASSWORD,
                }
            }
        },
        {
            xml = "saml:AttributeStatement",
            {
                xml            = "saml:Attribute",
                ["Name"]       = "uid",
                ["NameFormat"] = SAML_ATTR_NAME_FMT.BASIC,
                {
                    xml          = "saml:AttributeValue",
                    ["xsi:type"] = "xs:string",
                    nil,
                },
            },
        },
    }

    local resp = create_saml_response()

    ck.IssueInstant = resp.IssueInstant
    ck.ID = resp.ID

    resp:insert(ck)

    return resp
end

function create_saml_logout()
    local saml_logout_response = {
        xml              = "samlp:LogoutResponse",
        ["xmlns:samlp"]  = SAML_PROTO.V2_0,
        ["xmlns:saml"]   = "urn:oasis:names:tc:SAML:2.0:assertion",
        ["ID"]           = nil,
        ["Version"]      = "2.0",
        ["IssueInstant"] = nil,
        ["Destination"]  = nil,
        ["InResponseTo"] = nil,
        {
            xml = "saml:Issuer",
            nil,
        },
        {
            xml = "samlp:Status",
            {
                xml       = "samlp:StatusCode",
                ["Value"] = SAML_STATUS.SUCCESS,
            }
        },
    }

    return saml_logout_response
end
