# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Shib dict."""

shib_dict = {
    "dataSource": "/saml/discofeed",
    "defaultReturn": "https://invenio01-demo.tugraz.at/saml/login/authn-request",
    "redirectAllow": [
        "^https://invenio01-demo\\.tugraz\\.at/.*$",
        "^https://invenio01-demo\\.tugraz\\.at$",
        "^https://127.0.0.1:5000/.*",
        # NOTE: tugraz\\.at.* is vulnerable, e.g. tugraz\\.atu/malicious
    ],
    "preferredIdP": ["https://login.uni-hamburg.de/idp/shibboleth"],
    "ignoreURLParams": False,
}
