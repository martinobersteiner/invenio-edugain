# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

# TODO: configuration should be more convenient
#       consider renaming this file and rewording file's docstring when doing so
"""Config for pysaml2."""

from saml2 import BINDING_HTTP_POST
from saml2.attributemaps.saml_uri import MAP
from saml2.entity_category.edugain import COC
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.saml import NAME_FORMAT_BASIC, NAME_FORMAT_URI
from saml2.sigver import get_xmlsec_binary
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

NAME_FROM_FRIENDLYNAME: dict[str, str] = MAP["to"]

NS_PREFIX = {
    "alg": "urn:oasis:names:tc:SAML:metadata:algsupport",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "eidas": "http://eidas.europa.eu/saml-extensions",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "mdattr": "urn:oasis:names:tc:SAML:metadata:attribute",
    "mdui": "urn:oasis:names:tc:SAML:metadata:ui",
    "remd": "http://refeds.org/metadata",
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
}
"""Names for namespaces that SAML commonly uses."""


sp_config_dict = {
    # others from SPEC['sp']
    "allow_unsolicited": True,
    "authn_requests_signed": False,
    "digest_algorithm": DIGEST_SHA256,
    "endpoints": {
        "assertion_consumer_service": [
            ("https://localhost:5000/saml/acs", BINDING_HTTP_POST),
        ],
    },
    "force_authn": False,  # doesn't show yet...  # tugraz-mail SSO uses this, should it though?
    "name_id_format_allow_create": True,  # TODO: this wont show in <AuthnRequest> unless the next line is specified too
    "optional_attributes": [
        "eduPersonPrincipalName",
        "eduPersonScopedAffiliation",
        "uid",
    ],
    "signing_algorithm": SIG_RSA_SHA256,
    "requested_attributes": [],  # TODO
    "required_attributes": [
        "displayName",
        "givenName",
        "mail",
        "sn",
        "subject-id",
    ],
    "ui_info": {  # TODO
        "description": [
            {"text": "ui desc en", "lang": "en"},
            {"text": "ui desc de", "lang": "de"},
        ],
        "display_name": [
            {"text": "ui disp en", "lang": "en"},
            {"text": "ui disp de", "lang": "de"},
        ],
        "information_url": [
            {"text": "ui info-url en", "lang": "en"},
            {"text": "ui info-url de", "lang": "de"},
        ],
        "logo": {
            "height": "",
            "width": "",
            "text": "https://url-to-logo.jpg",
        },
        "privacy_statement_url": "url",
    },
    "want_assertions_signed": False,
    "want_assertions_or_response_signed": True,
    "want_response_signed": False,
}


config_dict = {
    "contact_person": [
        {
            "email_address": ["mailto:"],  # TODO: mail
            "givenname": "Technical",
            "surname": "Support",
            "contact_type": "technical",
        },
        {
            "email_address": ["mailto:"],  # TODO: mail
            "extension_attributes": {
                "xmlns:remd": "http://refeds.org/metadata",
                "remd:contactType": "http://refeds.org/metadata/contactType/security",
            },
            "givenname": "Security",
            "surname": "Contact",
            "contact_type": "other",
        },
    ],
    "description": (
        "Desc en",
        "en",
    ),  # NOTE: due to internal config-representation in pysaml2, only one description can be given
    "entityid": "https://localhost:5000/edugain/sp",  # used for <Issuer> element  # TODO: compute from flask-config
    "entity_attributes": [
        {
            "name": NAME_FROM_FRIENDLYNAME["displayName"],
            "required": True,
        },
        {
            "name": NAME_FROM_FRIENDLYNAME["eduPersonPrincipalName"],
        },
        {
            "name": NAME_FROM_FRIENDLYNAME["eduPersonScopedAffiliation"],
        },
        {
            "name": NAME_FROM_FRIENDLYNAME["givenName"],
            "name_format": NAME_FORMAT_BASIC,
            "required": True,
        },
        {
            "name": NAME_FROM_FRIENDLYNAME["mail"],
            "required": True,
        },
        {
            "name": NAME_FROM_FRIENDLYNAME["sn"],
            "name_format": NAME_FORMAT_BASIC,
            "required": True,
        },
        {
            "name": NAME_FROM_FRIENDLYNAME["uid"],
        },
        {
            "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "name": "urn:oasis:names:tc:SAML:profiles:subject-id:req",  # TODO: there a var for this?
            "values": ["any"],
        },
    ],
    "entity_category": [COC, RESEARCH_AND_SCHOLARSHIP],
    "metadata": [
        {
            "class": "invenio_edugain.utils.MetaDataFlaskSQL",
            "metadata": [(None,)],
        },
    ],
    "name": (
        "name en",
        "en",
    ),  # NOTE: due to internal config-representation in pysaml2, only one name can be given
    "name_form": NAME_FORMAT_URI,  # TODO: what does this do?
    "organization": {
        "name": [
            ("en org-name", "en"),
            ("de org-name", "de"),
        ],
        "display_name": [
            ("en disp-name", "en"),
            ("de disp-name", "de"),
        ],
        "url": [
            ("en org-url", "en"),
            ("de org-url", "de"),
        ],
    },
    "service": {
        "sp": sp_config_dict,
    },
    "key_file": "pki/mykey.pem",
    "cert_file": "pki/mycert.pem",
    "encryption_keypairs": [
        # security best practice is to never use the same key for two things
        # (probably doesn't really matter in this case in particular though)
        {"key_file": "pki/mykey.pem", "cert_file": "pki/mycert.pem"},
    ],
    "xmlsec_binary": get_xmlsec_binary(["/opt/local/bin", "usr/local/bin"]),
}
