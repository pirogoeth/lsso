--
-- saml.lua -- module that handles SAML communication
--

module('saml', package.seeall)

-- Lua standard and external library imports
local os = require "os"
local xml = require "xml"

-- Internal library imports
local session = require "session"
local util = require "util"

-- SAML protocol constants
local SAML_STATUS = {
    SUCCESS_URI                  = "urn:oasis:names:tc:SAML:2.0:status:Success",
    REQUESTER_URI                = "urn:oasis:names:tc:SAML:2.0:status:Requester",
    RESPONDER_URI                = "urn:oasis:names:tc:SAML:2.0:status:Responder",
    VERSION_MISMATCH_URI         = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
    AUTHN_FAILED_URI             = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
    INVALID_ATTR_NAME_VALUE_URI  = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
    INVALID_NAMEID_POLICY_URI    = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
    NO_AUTHN_CONTEXT_URI         = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
    NO_AVAIL_IDP_URI             = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
    NO_SUPPORTED_IDP_URI         = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
    PARTIAL_LOGOUT_URI           = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
    PROXY_COUNT_EXCESS_URI       = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
    REQ_DENIED_URI               = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
    REQ_UNSUPPORTED_URI          = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
    REQ_VERSION_DEPRECATED_URI   = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated",
    REQ_VERSION_TOO_HIGH_URI     = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh",
    REQ_VERSION_TOO_LOW_URI      = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
    RESOURCE_UNKNOWN_URI         = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized",
    TOO_MANY_RESPONSES_URI       = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
    UNKNOWN_ATTR_PROFILE_URI     = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile",
    UNKNOWN_PRINCIPAL_URI        = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
    UNSUPPORTED_BINDING_URI      = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding",
}

local SAML_NAMEID = {
    TRANSIENT                    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    PERSISTENT                   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    ENTITY                       = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
    X509_SUBJECT                 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
    EMAIL_ADDR                   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    UNSPECIFIED                  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
}

local SAML_CM = {
    BEARER                       = "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    H_O_K                        = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    SENDER_VOUCHES               = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches",
}

local SAML_AUTHN_CTX_REF = {
    PASSWORD                     = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
}

local SAML_ATTR_NAME_FMT = {
    BASIC                        = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
}

-- SAML protocol responses
local saml_authn_response = {
    xml = "samlp:Response",
    ["xmlns:samlp"]  = "urn:oasis:names:tc:SAML:2.0:protocol",
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
        xml       = "samlp:Status",
        ["Value"] = SAML_STATUS.SUCCESS_URI,
    },
    {
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
    },
}

local saml_logout_response = {
    xml              = "samlp:LogoutResponse",
    ["xmlns:samlp"]  = "urn:oasis:names:tc:SAML:2.0:protocol",
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
