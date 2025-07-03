# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""invenio-edugain views."""

# import traceback  # except Exception as e: return traceback.format_exception(e) # noqa: ERA001
from xml.etree import ElementTree as ET

from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    current_app,
    redirect,
    render_template,
    request,
)
from flask_security import login_user
from saml2.client import Saml2Client
from saml2.config import Config, SPConfig
from saml2.metadata import entity_descriptor
from werkzeug.wrappers import Response as BaseResponse

from .utils import (
    NS_PREFIX,
    AuthnInfo,
    AuthnResponseError,
    create_user,
    get_idp_data_dict,
)


def debug_return_error(func):
    """For debugging purposes: return formatted call-stack trace rather than 404 page."""
    import functools

    @functools.wraps(func)
    def decoed():
        try:
            return func()
        except Exception as e:
            from traceback import format_exception

            return format_exception(e)

    return decoed


@debug_return_error
def login_discover() -> str:
    """Discovery page for chosing an IdP."""
    return render_template(
        "invenio_edugain/login_discovery_eds.html",
        # idp_data_dict=get_idp_data_dict(),
    )


def disco_feed() -> list:
    """Return disco feed for use with shibboleth EDS."""
    idps_dict = get_idp_data_dict()

    from saml2.client import Saml2Client
    from saml2.mdstore import MetadataStore

    config_dict = current_app.config["EDUGAIN_PYSAML2_CONFIG"]
    config = Config()
    config.load(config_dict)
    mds: MetadataStore = config.metadata

    idp_ids: list[str] = sorted(mds.identity_providers())
    feed = []
    for idp_id in idp_ids:
        entry: dict[str, list | str] = {"entityID": idp_id}
        uiinfos = list(
            mds.mdui_uiinfo(idp_id)
        )  # TODO: might containt duplicates: dedup
        entry["DisplayNames"] = [
            {"lang": dn["lang"], "value": dn["text"]}
            for uiinfo in uiinfos
            for dn in uiinfo.get("display_name", [])
        ]
        entry["Keywords"] = [
            {"lang": kw["lang"], "value": kw["text"]}
            for uiinfo in uiinfos
            for kw in uiinfo.get("keywords", [])
        ]
        entry["Logos"] = [
            {"value": logo["text"], "height": logo["height"], "width": logo["width"]}
            for uiinfo in uiinfos
            for logo in uiinfo.get("logo", [])
        ]
        feed.append(entry)

    return feed

    return [
        {
            "entityID": idp_id,
            "DisplayNames": [{"lang": "en", "value": idp_data["displayname"]}],
            "Keywords": [],
            "Logos": [{"value": idp_data["logo_url"], "width": 70, "height": 70}],
        }
        for idp_id, idp_data in idps_dict.items()
    ] + [
        {
            "entityID": "https://weblogin.univie.ac.at/shibboleth/full",
            "DisplayNames": [
                {"value": "Universität Wien", "lang": "de"},
                {"value": "University of Vienna", "lang": "en"},
            ],
            "Keywords": [
                {"value": "uni+wien uniwien universitaet", "lang": "de"},
                {
                    "value": "uni+wien uniwien universität universitaet wien",
                    "lang": "en",
                },
            ],
            "Logos": [
                {
                    "value": "https://zid.univie.ac.at/fileadmin/user_upload/d_zid/open/formulare/eduid/logo_uniwien_250.png",
                    "height": "70",
                    "width": "250",
                },
                {
                    "value": "https://zid.univie.ac.at/fileadmin/user_upload/d_zid/open/formulare/eduid/logo_uniwien_16.png",
                    "height": "16",
                    "width": "16",
                },
            ],
        },
    ]


# TODO: consider using a FlaskResource for the following functions
def authn_request() -> BaseResponse:
    """Send an authorization-request to IdP depending on `request.args`.

    request.args["id"] identifies the IdP to send the request to
    request.args["next"] determines where to redirect to after response
    """
    # parse search params for entityid, next
    entityid = request.args.get("entityID")  # TODO: was 'id' in old version
    if entityid is None:
        abort(400, description="Missing required parameter: id")
    # TODO: this doesn't translate relative to absolute url, should be translated?
    relay_state = request.args.get("next", "/")  # TODO: make default configurable
    # TODO: if next is /saml/login or /login or something weird like that, then use `/` instead

    # pysaml2: create authn-request
    config_dict = current_app.config["EDUGAIN_PYSAML2_CONFIG"]
    config = SPConfig()
    config.load(config_dict)
    client = Saml2Client(config)
    # TODO: cache request-id to guard against replay attacks
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
    config_dict = current_app.config["EDUGAIN_PYSAML2_CONFIG"]
    config = Config()
    config.load(config_dict)
    ed = entity_descriptor(config)

    # TODO: consider removing this, as it's just an string-representation cleanup
    # clean up xml-representation
    ed_etree = ET.XML(ed.to_string(NS_PREFIX))
    ET.indent(ed_etree)
    xml_bytes = ET.tostring(ed_etree, xml_declaration=True)

    return Response(xml_bytes, mimetype="application/xml")


from .debug import log_error, logger


@log_error
def acs() -> BaseResponse:
    """Assertion consumer service."""  # noqa:D401
    next_url = request.form.get("RelayState")
    saml_response = request.form.get("SAMLResponse")
    if saml_response is None:
        msg = "POST contained no SAMLResponse"
        raise AuthnResponseError(msg)

    authn_info = AuthnInfo.from_saml_xml(saml_response)
    logger.debug(authn_info)
    if authn_info.user is None:
        # no user found in db, create one
        # TODO: the user might wanna link this login-info to an existing account...
        authn_info.user = create_user(authn_info)

    # TODO: register new affiliations/new login-methods/new ...

    if not login_user(authn_info.user):
        # user.active is False, hence wasn't logged in
        msg = "User was blocked/deactivated"
        raise AuthnResponseError(msg)
    current_app.extensions["security"].datastore.commit()

    # TODO: check for open redirect attacks: check next_url against flask.config['TRUSTED_HOSTS']
    #       does flask do this already?
    return redirect(next_url or current_app.config["SECURITY_POST_LOGIN_VIEW"])


# TODO: for debug only, don't merge this
def sp_json() -> dict:
    """Return pysaml2 configuration as dict."""
    return current_app.config["EDUGAIN_PYSAML2_CONFIG"]


# TODO: collect all over the place TODOs in one place
# pysaml2: `it is recommended that the entityid should point to a real webpage where the metadata for the entity can be found`
# TODO: required_attributes should only be part of configuration when building <EntityDescriptor>, but not when building <AuthnRequest>
# TODO: clicking back-and-forth between /login and /edugain/login messes up ?next=...
# TODO: don't load metadata from db on /edugain/sp
# TODO: the route /edugain/acs is duplicated in sp_config_dict, dedup this


def test() -> str:
    """Test."""
    return render_template(
        "invenio_edugain/test.html",
        # idp_data_dict=get_idp_data_dict(),
    )


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

    # note that app-entrypoints are loaded before blueprint-entrypoints, so this exists
    talisman = app.extensions.get("invenio-app", None).talisman
    default_csp = talisman.content_security_policy

    # this is a decorator for views that sets their Content-Security-Policy
    allow_imgsrc_csp = talisman(
        content_security_policy=default_csp | {"img-src": "*"},
    )
    # apply decorator (note that @decorator syntax is just syntactic sugar for calling the func)
    login_discover_allow_img = allow_imgsrc_csp(login_discover)

    blueprint.add_url_rule(routes["login-discover"], view_func=login_discover_allow_img)
    blueprint.add_url_rule(routes["authn-request"], view_func=authn_request)
    # NOTE: the next one is special, it's also the identifier of the SP to the federation
    blueprint.add_url_rule(routes["sp-xml"], view_func=sp_xml)

    # TODO: add configurable routes for these
    blueprint.add_url_rule(
        "/sp/json",
        view_func=sp_json,
    )  # TODO: to show pysaml2 config for registration purposes
    blueprint.add_url_rule("/acs", methods=["POST"], view_func=acs)
    blueprint.add_url_rule("/discofeed", view_func=disco_feed)

    blueprint.add_url_rule("/test", view_func=test)

    # TODO: consider registering error-handlers, context-processors, ...

    return blueprint
