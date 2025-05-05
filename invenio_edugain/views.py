# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""invenio-edugain views."""

import traceback
from xml.etree import ElementTree as ET

from flask import Blueprint, Response, render_template, request
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config, SPConfig
from saml2.metadata import entity_descriptor

from .saml_config import NS_PREFIX, config_dict, get_idp_data_dict

# TODO: consider def create_blueprint(url_prefix='')
blueprint = Blueprint(
    "invenio_edugain",
    __name__,
    static_folder="static",
    template_folder="templates",
)


# TODO: make routes configurable
# TODO: consider /login/edugain instead, which is the pattern invenio provides logins under...
@blueprint.route("/edugain/login")
def login() -> str:
    """Discovery page for chosing an IdP."""
    return render_template(
        "invenio_edugain/login_discovery.html",
        idp_data_dict=get_idp_data_dict(),
    )


# TODO: consider using a FlaskResource for the following two functions
@blueprint.route("/edugain/authn-request")
def authn_request():
    """Send an authorization-request to IdP depending on `request.args`.

    request.args["id"] identifies the IdP to send the request to
    request.args["next"] determines which to redirect to after response
    """
    try:
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
            ],  # TODO: consider translating relative to absolute url, default if not given  # TODO: use .get instead of [...]
            nsprefix=NS_PREFIX,
        )
        return {"request_id": request_id, "info": info}
    except Exception as e:
        return traceback.format_exception(e)


# TODO: the route /edugain/sp is duplicated from sp_config_dict (entitiy-id should show sp-metadata), dedup this
@blueprint.route("/edugain/sp")
def sp_xml() -> Response:
    """Show SAML xml-metadata of this service provider."""
    config = Config()
    config.load(config_dict)
    ed = entity_descriptor(config)

    # TODO: consider removing this, as it's just an string-representation cleanup
    et = ET.XML(ed.to_string(NS_PREFIX))
    ET.indent(et)
    xml_bytes = ET.tostring(et, xml_declaration=True)

    return Response(xml_bytes, mimetype="application/xml")


# TODO: the route /edugain/acs is duplicated here from sp_config_dict, dedup this
@blueprint.route("/edugain/acs", methods=["POST"])
def acs():
    """Assertion consumer service."""
    config = SPConfig()
    config.load(config_dict)
    client = Saml2Client(config)

    # TODO: try-except for better error?
    authn_response = client.parse_authn_request_response(
        request.form["SAMLResponse"],
        BINDING_HTTP_POST,
    )
    return authn_response.get_identity()


# TODO: collect all over the place TODOs in one place

# pysaml2: `it is recommended that the entityid should point to a real webpage where the metadata for the entity can be found`
# TODO: required_attributes should only be part of configuration when building <EntityDescriptor>, but not when building <AuthnRequest>
# TODO: clicking back-and-forth between /login and /edugain/login messes up ?next=...
# TODO: don't load metadata from db on /edugain/sp
