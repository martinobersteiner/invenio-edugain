# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""invenio-edugain views."""

# import traceback  # except Exception as e: return traceback.format_exception(e) # noqa: ERA001
from xml.etree import ElementTree as ET

from flask import Blueprint, Flask, Response, abort, redirect, render_template, request
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config, SPConfig
from saml2.metadata import entity_descriptor
from werkzeug.wrappers import Response as BaseResponse

from .saml_config import NS_PREFIX, config_dict
from .utils import get_idp_data_dict


def login_discover() -> str:
    """Discovery page for chosing an IdP."""
    return render_template(
        "invenio_edugain/login_discovery.html",
        idp_data_dict=get_idp_data_dict(),
    )


# TODO: consider using a FlaskResource for the following functions
def authn_request() -> BaseResponse:
    """Send an authorization-request to IdP depending on `request.args`.

    request.args["id"] identifies the IdP to send the request to
    request.args["next"] determines where to redirect to after response
    """
    # parse search params for entityid, next
    entityid = request.args.get("id")
    if entityid is None:
        abort(400, description="Missing required parameter: id")
    # TODO: this doesn't translate relative to absolute url, should be translated?
    relay_state = request.args.get("next", "/")  # TODO: make default configurable
    # TODO: if next is /saml/login or /login or something weird like that, then use `/` instead

    # pysaml2: create authn-request
    config = SPConfig()
    config.load(config_dict)
    client = Saml2Client(config)
    # TODO: cache request-id to guard against replay attacks
    breakpoint()
    request_id, http_args = client.prepare_for_authenticate(
        entityid=entityid,
        relay_state=relay_state,
        nsprefix=NS_PREFIX,
    )

    # create flask redirect from pysaml2
    redirect_urls = [
        header_value
        for header_name, header_value in http_args["headers"]
        if header_name == "Location"
    ]
    if len(redirect_urls) != 1:
        # this shouldn't ever happen...
        msg = "pysaml2 gave multiple redirect urls"
        raise ValueError(msg)
    redirect_url = redirect_urls[0]
    redirect_kwargs = {}
    if http_status_code := http_args.get("status"):
        redirect_kwargs["code"] = http_status_code

    return redirect(redirect_url, **redirect_kwargs)


# TODO: the route /saml/sp/xml is duplicated from sp_config_dict (entitiy-id should show sp-metadata), dedup this
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
def acs() -> str:
    """Assertion consumer service."""  # noqa:D401
    ava = {}
    try:
        config = SPConfig()
        config.load(config_dict)
        client = Saml2Client(config)

        # TODO: try-except for better error?
        from saml2.response import AuthnResponse

        authn_response: AuthnResponse = client.parse_authn_request_response(
            request.form["SAMLResponse"],
            BINDING_HTTP_POST,
        )
        if authn_response is None:
            abort(500, description="Bad SAMLResponse")

        # TODO: log debug.log somewhere
        # ava (attribute value assertions) is dict: friendlyName->list[str]
        ava = authn_response.get_identity()
        mail = ava.get("mail", [None])[0]
        ids = {
            "pairwise-id": ava.get("pairwise-id", [None])[0],
            "subject-id": ava.get("subject-id", [None])[0],
            "ePPN": ava.get("eduPersonPrincipalName", [None])[0],
        }
        given_name = ava["givenName"][0]
        family_name = ava["sn"][0]
    except Exception as exc:  # noqa: BLE001
        import json
        import traceback

        return (
            repr(traceback.format_exception(exc)) + "\n\n" + json.dumps(ava, indent=2)
        )

    from datetime import datetime, timezone

    from flask import current_app
    from invenio_accounts.models import UserIdentity
    from invenio_db import db
    from invenio_oauthclient.utils import (
        create_csrf_disabled_registrationform,
        fill_form,
    )
    from werkzeug.local import LocalProxy

    _security = LocalProxy(lambda: current_app.extensions["security"])
    _datastore = LocalProxy(lambda: _security.datastore)  # type: ignore[attr-defined]

    if all(id_ is None for id_ in ids.values()):
        abort()  # or raise instead?
    for method, id_ in ids.values():
        if user := UserIdentity.get_user(method, id_):
            break

    if user is None:
        # create new user
        form = create_csrf_disabled_registrationform("edugain")
        form = fill_form(
            form,
            {"email": mail, "profile": {"full_name": given_name + " " + family_name}},
        )
        if form.validate():
            # see invenio_saml.invenio_accounts.utils:account_register
            confirmed_at = (
                datetime.now(timezone.utc)
                if remote_app_config.get("auto_confirm", False)
                else None
            )
            data = {
                **form.to_dict(),
                "confirmed_at": confirmed_at,
            }
            if not data.get("password"):
                data["password"] = ""
            user = register_user(**data)
            if not data["password"]:
                user.password = None
            _datastore.commit()
        db.session.commit()

    if user is None or not account_authenticate(user):
        abort(401)

    account_setup(user, {...: ...})
    next_url = request.args.get("RelayState")
    return (
        get_safe_redirect_target(_target=next_url)
        or current_app.config["SECURITY_POST_LOGIN_VIEW"]
    )


# TODO: for debug only, don't merge this
def sp_json() -> dict:
    """Return pysaml2 configuration as dict."""
    return config_dict


# TODO: collect all over the place TODOs in one place

# pysaml2: `it is recommended that the entityid should point to a real webpage where the metadata for the entity can be found`
# TODO: required_attributes should only be part of configuration when building <EntityDescriptor>, but not when building <AuthnRequest>
# TODO: clicking back-and-forth between /login and /edugain/login messes up ?next=...
# TODO: don't load metadata from db on /edugain/sp


def create_blueprint(app: Flask) -> Blueprint:
    """Create blueprint for invenio-edugain."""
    routes = app.config["EDUGAIN_ROUTES"]
    blueprint = Blueprint(
        "invenio_edugain",
        __name__,
        static_folder="static",
        template_folder="templates",
        url_prefix="/saml",
    )

    # TODO: consider using create_url_rule, which allows changing function as well as rule
    blueprint.add_url_rule(routes["login-discover"], view_func=login_discover)
    blueprint.add_url_rule("/login/authn-request", view_func=authn_request)
    # NOTE: the next one is special, it's also the identifier of the SP to the federation
    blueprint.add_url_rule("/sp/xml", view_func=sp_xml)
    blueprint.add_url_rule("/sp/json", view_func=sp_json)
    blueprint.add_url_rule("/acs", methods=["POST"], view_func=acs)

    # TODO: consider registering error-handlers, context-processors, ...

    return blueprint
