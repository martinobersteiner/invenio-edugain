# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Config for pysaml2."""

# TODO: consider using a FlaskResource for the following API
# TODO: move these to other file(s)
import logging
import sys
from typing import Any

from invenio_db import db
from lxml import etree
from saml2 import BINDING_HTTP_POST
from saml2.attributemaps.saml_uri import MAP
from saml2.client import logger
from saml2.entity_category.edugain import COC
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.mdstore import InMemoryMetaData
from saml2.saml import NAME_FORMAT_BASIC, NAME_FORMAT_URI
from saml2.sigver import get_xmlsec_binary
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

from .models import IdPData

NAME_FROM_FRIENDLYNAME: dict[str, str] = MAP["to"]


class AuthnHandler(logging.StreamHandler):
    def handle(self, record):
        if record.msg.startswith("AuthNReq: "):
            xml = record.args[0]

            root = etree.fromstring(xml)
            pretty_xml = etree.tostring(root, pretty_print=True).decode("utf-8")

            record.args = (pretty_xml,)

        return super().handle(record)


logger.setLevel(logging.DEBUG)
logger.addHandler(AuthnHandler(sys.stderr))


# TODO: cache
def get_idp_data_dict() -> dict:
    query = db.select(IdPData)
    idps_data: list[IdPData] = db.session.execute(query).scalars()

    return {
        idp_data.id: {
            "displayname": idp_data.displayname,
            "logo_url": idp_data.logo_url,
        }
        for idp_data in idps_data
        if idp_data.enabled
    }


class MetaDataFlaskSQL(InMemoryMetaData):
    """Loads single entity from SQL-db.

    This is akin to saml2.mdstore.MetaDataMD, which loads from file rather than from db.
    """

    def __init__(
        self,
        attrc: tuple | None,
        __: str,  # metadata loaders must always take a second positional arg, which doubles as id in MDStore
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        """Init."""
        super().__init__(attrc, **kwargs)

    # TODO: load only passed idp-id?
    # TODO: cache idp_settings somewhere?
    # TODO: pass some positional arg that actually does something? e.g. `db`
    def load(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401, ARG002
        """Load."""
        for idp in db.session.scalars(db.select(IdPData)):
            self.entity[idp.id] = idp.settings


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
            ("https://localhost:5000/edugain/acs", BINDING_HTTP_POST),
        ],
    },
    "force_authn": False,  # doesn't show yet...  # tugraz-mail SSO uses this, should it though?
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
            "class": "invenio_edugain.saml_config.MetaDataFlaskSQL",
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
