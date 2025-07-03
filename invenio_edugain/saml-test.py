"""Test pysaml2."""

from flask import redirect
from saml2 import BINDING_HTTP_POST  # , BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config, SPConfig
from saml2.entity_category.edugain import COC

try:
    # not always available...
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"])
else:
    xmlsec_path = "/usr/local/bin/xmlsec1"

config = Config()
config_dict = {
    # TODO: default sign_alg is xmldsig#rsa-sha1, default digest_alg is xmldsig#sha1, are these fine?
    # ...  # other keys from saml2.config.COMMON_ARGS
    "entityid": "http://domain:42/sp.xml",
    "entity_category": [COC],
    "description": "...",
    "service": {
        # 'aa': ...
        # 'idp': ...
        # 'pdp': ...
        # 'aq': ...
        "sp": {
            # keys from saml2.config.SPEC['sp'] == COMMON_ARGS + COMPLEX_ARGS + SP_ARGS
            "want_response_signed": True,
            "authn_requests_signed": True,
            # logout_requests_signed
            "endpoints": {
                "assertion_consumer_service": [
                    ("http://localhost:42/acs/post", BINDING_HTTP_POST),
                ],
                # single_logout_service
            },
        },
    },
    "key_file": ...,
    "cert_file": ...,
    "xmlsec_binary": xmlsec_path,
    "metadata": {  # old dict-style to load metadata
        "local": ["../path/to/file.xml"],
        "remote": [...],
    },
    "metadata": [  # new class-style for loading metadata  # noqa: F601
        {
            "class": "parent_module.module.MyClass",
            # `from parent_module.module import MyClass`
            "metadata": [("key-in-metadata", "cert"), ("other-name",)],
            # ^ means within this {}, . means config outermost
            # md = MyClass(.attrc, ^metadata[i][0], filter=.filter, cert=^metadata[i].get(1,missing))
            # md.load(); .metadata[key-in-metadata] = md
        },
    ],
    "name_form": "?",
    "extensions": {
        # these key-value pairs are set to config.extensions: dict
    },
}

# set known keys to attributes, ignore unknown keys
# .metadata = .load_metadata(config_dict['metadata'])
config.load(config_dict)


def login() -> None:
    """Login."""
    config = SPConfig()
    client = Saml2Client(config)
    # TODO: cache request_id to guard against replay-attacks
    request_id, info = client.prepare_for_authenticate(
        entityid="uri-of-recipient-idp",
        relay_state="uri-after-login",
    )
    redirect_url = dict(info["headers"])["Location"]

    redirect(redirect_url)


def assertion_consumer_service() -> None:
    """ACS."""
    client = Saml2Client(config)

    class Request:
        POST: dict[str, str] = {}  # noqa: RUF012

    request = Request()

    authn_response = client.parse_authn_request_response(
        request.POST[
            "SAMLResponse"
        ],  # request here is a django thing, gotta figure out flask equivalent...
        BINDING_HTTP_POST,
    )
    authn_response.authn_info()


from typing import Any  # noqa: E402

from invenio_db import db  # noqa: E402
from saml2.mdie import from_dict  # noqa: E402
from saml2.mdstore import (  # noqa: E402
    Config,
    InMemoryMetaData,
    MetaDataMD,
    MetadataStore,
    load_metadata_modules,
)

from invenio_edugain.models import IdPData  # noqa: E402

url = "https://..."
mds = MetadataStore(None, Config())
mds.load("remote", url=url)
idps: list[str] = mds.identity_providers()
for idp in idps:
    json = mds[idp]  # export internal is saml2.mdie:to_dict
    # import via saml2.mdie:from_dict
    entity_descriptor = from_dict(json, load_metadata_modules())
    xml: str = entity_descriptor.to_string()

    filepath = "/..."
    with MetaDataMD as load:
        json.dump(filepath, [(idp, json)])
        old_style_config = {"mdfile": [filepath]}
        cert = "otional"
        new_style_config = [
            {
                "class": "saml2.mdstore.MetaDataMD",
                "metadata": [(filepath, cert)],
            },
        ]


class MetaDataSQL(InMemoryMetaData):
    """Loads single entity from SQL-db."""

    def __init__(
        self,
        attrc: tuple | None,
        idp_id: str,
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        """Init."""
        super().__init__(attrc, **kwargs)
        self.idp_id = idp_id

    # TODO: load all and cache instead?
    def load(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401, ARG002
        """Load."""
        query = db.select(IdPData).where(IdPData.id == self.idp_id)
        idp = db.session.execute(query).one()
        self.entity[self.idp_id] = idp.settings


# the following is a way to translate a config.py with sp-config into xml-string
# this is due to perplexity.ai and hence probably buggy...

import os  # noqa: E402
import subprocess  # noqa: E402
import xml.etree.ElementTree as ET  # noqa: E402


def generate_metadata(config_path: os.PathLike) -> str:
    """GM."""
    result = subprocess.run(
        ["make_metadata.py", config_path],
        stdout=subprocess.PIPE,
        check=True,
        text=True,
    )
    metadata = ET.XML(result.stdout)
    ET.indent(metadata)
    return ET.tostring(metadata, encoding="unicode")
