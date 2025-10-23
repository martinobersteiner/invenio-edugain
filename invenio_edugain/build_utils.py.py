"""Build utils."""

from typing import Any
from urllib.parse import urlparse, urlunparse

from flask import Flask
from invenio_base.urls.helpers import invenio_url_for
from saml2 import BINDING_HTTP_POST


def build(app: Flask) -> dict:
    """Build."""
    res: dict[str, Any] = {}

    # TODO: invenio_url_for?
    try:
        non_existent_sentinel = object()
        previous_server_name = app.config.get("SERVER_NAME", non_existent_sentinel)
        app.config["SERVER_NAME"] = "dummy.org"
        acs_parsed = urlparse(app.url_for("invenio_edugain.acs"))
    finally:
        if previous_server_name is non_existent_sentinel:
            del app.config["SERVER_NAME"]
        else:
            app.config["SERVER_NAME"] = previous_server_name

    server_routes: list[str] = app.config["EDUGAIN_"]
    acs_urls = []
    for server_route in server_routes:
        server_parsed = urlparse(server_route)
        acs_urls.append(
            urlunparse(
                (
                    server_parsed.scheme or "https",
                    server_parsed.netloc,
                    acs_parsed.path,
                    "",
                    "",
                    "",
                ),
            ),
        )

    for acs_url in acs_urls:
        res["service"]["sp"]["acs"].append((acs_url, BINDING_HTTP_POST))

    return res
