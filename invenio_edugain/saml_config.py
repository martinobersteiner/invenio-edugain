# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

# TODO: configuration building
#       convenient low-friction configuration is a highly demanded feature
#       can't really just be a flask.current_app.config var, as it has attributes too dynamic for that
#         - something behind a werkzeug-proxy?
#         - some methods on the flask-extension for invenio-edugain?
#       it'll take some time to figure that out
#       in the meantime, here's a static config
"""Static config for our SP.

This is a static configuration for now, until configuration building is implemented.
"""

from saml2 import BINDING_HTTP_POST
from saml2.entity_category.edugain import COC
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.saml import NAME_FORMAT_URI
from saml2.sigver import get_xmlsec_binary
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

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
            ("https://127.0.0.1:5000/saml/acs", BINDING_HTTP_POST),
            ("https://repository.tugraz.at/saml/acs", BINDING_HTTP_POST),
            ("https://invenio01-demo.tugraz.at/saml/acs", BINDING_HTTP_POST),
        ],
    },
    "force_authn": False,  # doesn't show yet...  # tugraz-mail SSO uses this, should it though?
    "name_id_format_allow_create": True,  # NOTE: this only shows in <AuthnRequest> when "requested_attributes" is truthy
    "optional_attributes": [
        "eduPersonPrincipalName",
        "eduPersonScopedAffiliation",
    ],
    "signing_algorithm": SIG_RSA_SHA256,
    "requested_attributes": [],
    "required_attributes": [
        "displayName",
        "givenName",
        "mail",
        "sn",
    ],
    "ui_info": {
        "description": [
            {
                "text": "The TU Graz Repository is a platform of Graz University of Technology where scientific papers, research data and open educational resources are collected, stored and made publicly available on a long-term basis. It serves to promote open access, open educational resources and participation in open science activities.",
                "lang": "en",
            },
            {
                "text": "Das TU Graz Repository ist eine Plattform der Technischen Universität Graz, auf der wissenschaftliche Arbeiten, Forschungsdaten und offene Bildungsressourcen nachhaltig gesammelt, gespeichert und öffentlich zugänglich gemacht werden. Es dient der Förderung von Open Access, Open Educational Resources und der Teilhabe an Open-Science-Aktivitäten.",
                "lang": "de",
            },
        ],
        "display_name": [
            {"text": "TU Graz Repository", "lang": "en"},
            {"text": "TU Graz Repository", "lang": "de"},
        ],
        "information_url": [
            {"text": "https://repository.tugraz.at/", "lang": "en"},
            {"text": "https://repository.tugraz.at/", "lang": "de"},
        ],
        "logo": [
            {
                "height": "177",
                "width": "177",
                "text": "https://repository.tugraz.at/static/images/library_logo.png",
            },
        ],
        "privacy_statement_url": [
            {
                "text": "https://repository.tugraz.at/static/documents/TUGraz_Repository_General_Data_Protection_Rights_en.pdf",
                "lang": "en",
            },
            {
                "text": "https://repository.tugraz.at/static/documents/TUGraz_Repository_General_Data_Protection_Rights_de.pdf",
                "lang": "de",
            },
        ],
    },
    "want_assertions_signed": False,
    "want_assertions_or_response_signed": True,
    "want_response_signed": False,
}

logging_config_dict = {
    "version": 1,
    "formatters": {
        "simple": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s",
        },
    },
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": "/home/obersteiner/repositories/martinobersteiner/invenio-edugain/invenio_edugain/log.log",
            "level": "DEBUG",
            "formatter": "simple",
        },
    },
    "loggers": {
        "saml2": {"level": "DEBUG"},
    },
    "root": {
        "level": "DEBUG",
        "handlers": [
            "file",
        ],
    },
}


config_dict = {
    "accepted_time_diff": 60,  # IdPs' clock may drift from our server's clock by this many seconds
    "allow_unknown_attributes": True,  # IdPs can send wildly different attributes, allow all of them to appear in parsed output
    "contact_person": [
        {
            "email_address": ["mailto:repository-support@tugraz.at"],
            "given_name": "Technical",
            "sur_name": "Support",
            "contact_type": "technical",
        },
        {
            "email_address": ["mailto:repository-support@tugraz.at"],
            "extension_attributes": {
                "xmlns:remd": "http://refeds.org/metadata",
                "remd:contactType": "http://refeds.org/metadata/contactType/security",
            },
            "given_name": "Security",
            "sur_name": "Contact",
            "contact_type": "other",
        },
    ],
    "description": (
        "The TU Graz Repository is a platform of Graz University of Technology where scientific papers, research data and open educational resources are collected, stored and made publicly available on a long-term basis. It serves to promote open access, open educational resources and participation in open science activities.",
        "en",
    ),  # NOTE: due to internal config-representation in pysaml2, only one description can be given
    "entityid": "https://repository.tugraz.at/saml/sp/xml",  # used for <Issuer> element  # TODO: compute from flask-config
    "entity_attributes": [
        {
            "format": NAME_FORMAT_URI,
            "name": "urn:oasis:names:tc:SAML:profiles:subject-id:req",
            "values": ["any"],
        },
    ],
    "entity_category": [COC, RESEARCH_AND_SCHOLARSHIP],
    "http_client_timeout": 10,
    "logging": logging_config_dict,
    "metadata": [
        {
            "class": "invenio_edugain.utils.MetaDataFlaskSQL",
            "metadata": [(None,)],
        },
    ],
    # NOTE: str() of name is used as ProviderName in AuthnRequests, so don't use (lang, text) tuple here;
    #       this is hence interpreted as default-language "en"
    #       (due to internal config-representation in pysaml2, only one language would be givable anyway)
    "name": "TU Graz Repository",
    "organization": {
        "name": [
            ("Graz University of Technology", "en"),
            ("Technische Universität Graz", "de"),
        ],
        "display_name": [
            ("Graz University of Technology", "en"),
            ("Technische Universität Graz", "de"),
        ],
        "url": [
            ("https://www.tugraz.at/en/home", "en"),
            ("https://www.tugraz.at/home", "de"),
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
    "xmlsec_binary": get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"]),
}
