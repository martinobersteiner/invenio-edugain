# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""invenio-edugain views."""

from collections import defaultdict
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
from invenio_oauthclient.utils import get_safe_redirect_target
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


def debug_return_error(func):  # noqa: ANN001, ANN201
    """For debugging purposes: return formatted call-stack trace rather than 404 page."""
    import functools  # noqa: PLC0415

    @functools.wraps(func)
    def decoed():  # noqa: ANN202
        try:
            return func()
        except Exception as e:  # noqa: BLE001
            from traceback import format_exception  # noqa: PLC0415

            return format_exception(e)

    return decoed


@debug_return_error
def login_discover() -> str:
    """Discovery page for chosing an IdP."""
    return render_template(
        "invenio_edugain/login_discovery_eds.html",
    )


@debug_return_error
def disco_feed() -> list:
    """Return disco feed for use with shibboleth EDS."""
    from saml2.mdstore import MetadataStore

    config_dict = current_app.config["EDUGAIN_PYSAML2_CONFIG"]
    config = Config()
    config.load(config_dict)
    mds: MetadataStore = config.metadata

    idp_ids: list[str] = sorted(mds.identity_providers())
    feed = []
    for idp_id in idp_ids:
        entry: dict[str, list | str] = {"entityID": idp_id}
        org = mds[idp_id].get("organization", {})
        uiinfos = list(
            mds.mdui_uiinfo(idp_id)
        )  # TODO: might containt duplicates: dedup
        names_by_lang = defaultdict(list)  # names ordered by relevance
        for uiinfo in uiinfos:
            for dn in uiinfo.get("display_name", []):
                names_by_lang[dn["lang"]].append(dn["text"])
        for name_key in [
            "organization_display_name",
            "organization_name",
            "organization_url",
        ]:
            for name_dict in org.get(name_key, []):
                names_by_lang[name_dict["lang"]].append(name_dict["text"])

        entry["DisplayNames"] = [
            {"lang": lang, "value": names[0]} for lang, names in names_by_lang.items()
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


# TODO: consider using a FlaskResource for the following functions
def authn_request() -> BaseResponse:
    """Send an authorization-request to IdP depending on `request.args`.

    request.args["id"] identifies the IdP to send the request to
    request.args["next"] determines where to redirect to after response
    """
    # parse search params for entityid, next
    entityid = request.args.get("entityID")
    if entityid is None:
        abort(400, description="Missing required parameter: id")

    # "relay state" is SAML's name for "URL to redirect to after succesful login"
    relay_state: str = (
        get_safe_redirect_target(arg="next")
        or current_app.config.get("SECURITY_POST_LOGIN_VIEW")
        or "/"
    )
    # TODO: if next is /saml/login or /login or something weird like that, use defaults instead

    # pysaml2: create authn-request
    config_dict = current_app.config["EDUGAIN_PYSAML2_CONFIG"]
    config = SPConfig()
    config.load(config_dict)
    client = Saml2Client(config)

    # multiple ACS URLs may be configured for `client` (e.g. test-, prod-server)
    # find the ACS URL corresponding to the request's host
    host_url = request.host_url
    assertion_consumer_service_url = None
    for url in client.service_urls():
        if url.startswith(host_url):
            assertion_consumer_service_url = url
            break
    else:
        abort(400, description="No ACS configured for this host")

    # TODO: cache request-id to guard against replay attacks
    request_id, http_args = client.prepare_for_authenticate(
        entityid=entityid,
        relay_state=relay_state,
        nsprefix=NS_PREFIX,
        assertion_consumer_service_url=assertion_consumer_service_url,
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


def sp_xml() -> Response:
    """Show SAML xml-metadata of this service provider."""
    config_dict = current_app.config["EDUGAIN_PYSAML2_CONFIG"]
    config = Config()
    config.load(config_dict)
    ed = entity_descriptor(config)

    # clean up xml-representation
    ed_etree = ET.XML(ed.to_string(NS_PREFIX))
    ET.indent(ed_etree)
    xml_bytes = ET.tostring(ed_etree, xml_declaration=True, encoding="utf-8")

    return Response(
        xml_bytes,
        content_type="application/xml; charset=utf-8",
        mimetype="application/xml",
    )


from .debug import log_error, logger


@log_error
def acs() -> BaseResponse:
    """Assertion consumer service."""  # noqa:D401
    next_url = request.form.get("RelayState")
    # TODO: sanitize next_url
    saml_response = request.form.get("SAMLResponse")
    if saml_response is None:
        msg = "POST contained no SAMLResponse"
        raise AuthnResponseError(msg)

    authn_info = AuthnInfo.from_saml_response(saml_response)
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

    # TODO: check for open redirect attacks;
    #       check next_url against flask.config['TRUSTED_HOSTS']
    #         (does flask do this already?)
    return redirect(next_url or current_app.config["SECURITY_POST_LOGIN_VIEW"])


# TODO: for debug only, don't merge this
def sp_json() -> dict:
    """Return pysaml2 configuration as dict."""
    config = current_app.config["EDUGAIN_PYSAML2_CONFIG"]
    for key in [
        "key_file",
        "cert_file",
        "encryption_keypairs",
        "logging",
        "metadata",
        "xmlsec_binary",
    ]:
        if key in config:
            del config[key]
    return config


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

    blueprint.add_url_rule(routes["acs"], methods=["POST"], view_func=acs)
    blueprint.add_url_rule(routes["login-discover"], view_func=login_discover_allow_img)
    blueprint.add_url_rule(routes["authn-request"], view_func=authn_request)
    # NOTE: the next one is special, it's also the identifier of the SP to the federation
    # TODO: the route /saml/sp/xml is duplicated from sp_config_dict (entitiy-id should show sp-metadata), dedup this
    blueprint.add_url_rule(routes["sp-xml"], view_func=sp_xml)

    # TODO: add configurable routes for these
    blueprint.add_url_rule(
        "/sp/json",
        view_func=sp_json,
    )  # TODO: to show pysaml2 config for registration purposes
    blueprint.add_url_rule("/discofeed", view_func=disco_feed)

    blueprint.add_url_rule("/test", view_func=test)

    # TODO: consider registering error-handlers, context-processors, ...

    return blueprint
