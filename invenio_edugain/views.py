# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""invenio-edugain views."""

from flask import Blueprint, render_template

# TODO: consider def create_blueprint(url_prefix='')
blueprint = Blueprint(
    "invenio_edugain",
    __name__,
    static_folder="static",
    template_folder="templates",
)


# TODO: make routes configurable
@blueprint.route("/edugain/login")
def login() -> str:
    return render_template(
        "invenio_edugain/login_discovery.html",
        idp_data_dict=get_idp_data_dict(),
    )


from invenio_db import db

from .models import IdPData


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


# TODO: consider using a FlaskResource for the following API
# TODO: move these to other file(s)
import logging
import sys
import traceback
from typing import Any

from flask import request
from lxml import etree
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client, logger
from saml2.config import SPConfig
from saml2.mdstore import InMemoryMetaData
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256


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


@blueprint.route("/edugain/authn-request")
def authn_request():
    try:
        config_dict = {
            "service": {
                "sp": {
                    # others from SPEC['sp']
                    "authn_requests_signed": True,
                    "digest_algorithm": DIGEST_SHA256,
                    "endpoints": {
                        "assertion_consumer_service": [
                            ("https://localhost:5000/edugain/acs", BINDING_HTTP_POST),
                        ],
                    },
                    # the following should cause a different SP-xml to be generated I think?
                    "entity_attributes": [
                        {
                            # "friendly_name": ?  # TODO: this needed?
                            "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                            "name": "urn:oasis:names:tc:SAML:profiles:subject-id:req",
                            "values": ["any"],
                        },
                    ],
                    "force_authn": False,  # doesn't show yet...  # tugraz-mail SSO uses this, should it though?
                    "signing_algorithm": SIG_RSA_SHA256,
                },
            },
            "metadata": [
                {
                    "class": "invenio_edugain.views.MetaDataFlaskSQL",
                    "metadata": [(None,)],
                },
                # TODO: load SP-config here, <Issuer> will be populated from this
            ],
            "key_file": "pki/mykey.pem",
            "cert_file": "pki/mycert.pem",
            # TODO: "xmlsec_binary"
        }
        config = SPConfig()
        config.load(config_dict)
        client = Saml2Client(config)
        # TODO: cache request-id to guard against replay attacks
        request_id, info = client.prepare_for_authenticate(
            entityid=request.args[
                "id"
            ],  # TODO: better error-message if doesn't exist...
            relay_state=request.args[
                "next"
            ],  # TODO: consider translating relative to absolute url, default if not given
            nsprefix={  # namespaces for the created <AuthnRequest>
                "ds": "http://www.w3.org/2000/09/xmldsig#",
                "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
                "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
        )
        return {"request_id": request_id, "info": info}
    except Exception as e:
        return traceback.format_exception(e)


# next:
#   key_file, cert_file
#   get AuthnRequest XML right before it's b64-encoded
#   endpoint for acs

# TODO: collect all over the place TODOs in one place
