# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Build configuration for pysaml2."""
from flask import Flask
from saml2 import BINDING_HTTP_POST
from saml2.entity_category.edugain import COC
from saml2.entity_category.refeds import RESEARCH_AND_SCHOLARSHIP
from saml2.saml import NAME_FORMAT_URI
from saml2.sigver import get_xmlsec_binary
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

from .pysaml2_core import Pysaml2ConfigCore
from .utils import url_for_server

type TupleJSON = (
    str
    | int
    | float
    | bool
    | None
    | dict[str, TupleJSON]
    | list[TupleJSON]
    | tuple[TupleJSON, ...]
)  # like JSON, except its values may also be tuples


def build_pysaml2_config(
    app: Flask,
    config_core: Pysaml2ConfigCore,
) -> dict[str, TupleJSON]:
    """Build configuration for use with pysaml2."""
    # contacts
    contacts: list[TupleJSON] = [
        {
            "email_address": [
                f"mailto:{config_core.contact.technical_support_email.normalized}",
            ],
            "given_name": config_core.contact.technical_support_given_name,
            "sur_name": config_core.contact.technical_support_sur_name,
            "contact_type": "technical",
        },
        {
            "email_address": [
                f"mailto:{config_core.contact.security_contact_email.normalized}",
            ],
            "extension_attributes": {
                "xmlns:remd": "http://refeds.org/metadata",
                "remd:contactType": "http://refeds.org/metadata/contactType/security",
            },
            "given_name": config_core.contact.security_contact_given_name,
            "sur_name": config_core.contact.security_contact_sur_name,
            "contact_type": "other",
        },
    ]

    # entity_categories
    entity_categories = []
    if config_core.category.coc_compliant:
        entity_categories.append(COC)
    if config_core.category.refeds_compliant:
        entity_categories.append(RESEARCH_AND_SCHOLARSHIP)

    # organization
    organization: dict[str, TupleJSON] = {}
    organization["name"] = [
        (name, lang_code) for lang_code, name in config_core.org.names_by_lang.items()
    ]
    organization["display_name"] = [
        (display_name, lang_code)
        for lang_code, display_name in config_core.org.displaynames_by_lang.items()
    ]
    organization["url"] = [
        (url, lang_code) for lang_code, url in config_core.org.urls_by_lang.items()
    ]

    return {
        "accepted_time_diff": 60,  # IdPs' clock may drift from our server's clock by this many seconds
        "allow_unknown_attributes": True,  # IdPs can send wildly different attributes, allow all of them to appear in parsed output
        "contact_person": contacts,
        "description": (
            config_core.service.description_en,
            "en",
        ),  # NOTE: due internal config-representation in pysaml2, only one description can be given
        "entityid": url_for_server(
            app,
            config_core.server_domain_main,
            "invenio_edugain.sp_xml",
        ),
        "entity_attributes": [
            {
                "format": NAME_FORMAT_URI,
                "name": "urn:oasis:names:tc:SAML:profiles:subject-id:req",
                "values": ["any"],
            },
        ],
        "entity_category": entity_categories,
        "http_client_timeout": 10,
        "logging": {},  # TODO: this
        "metadata": [  # configure metadata-loader that loads from SQL
            {
                "class": "invenio_edugain.utils.MetaDataFlaskSQL",
                "metadata": [(None,)],
            },
        ],
        # NOTE: str() of name is used as ProviderName in AuthnRequests, so don't use (lang, text) tuple here;
        #       this is hence interpreted as default-language "en"
        #       (due to internal config-representation in pysaml2, only one language would be givable anyway)
        "name": config_core.service.name_en,
        "organization": organization,
        "service": {
            "sp": build_sp(app, config_core),
        },
        "cert_file": str(config_core.credentials.signing_cert_filepath),
        "key_file": str(config_core.credentials.signing_key_filepath),
        "encryption_keypairs": [
            {
                "key_file": str(config_core.credentials.encryption_key_filepath),
                "cert_file": str(config_core.credentials.encryption_cert_filepath),
            },
        ],
        "xmlsec_binary": get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"]),
    }


def build_sp(app: Flask, core_config: Pysaml2ConfigCore) -> dict[str, TupleJSON]:
    """Build 'sp' part of a pysaml2 configuration."""
    # acs_enpoints
    acs_endpoints: list[TupleJSON] = [
        (url_for_server(app, domain, "invenio_edugain.acs"), BINDING_HTTP_POST)
        for domain in [
            core_config.server_domain_main,
            *core_config.server_domain_others,
        ]
    ]

    # ui-info
    ui_info: dict[str, TupleJSON] = {}
    ui_info["description"] = [
        {"text": text, "lang": lang_code}
        for lang_code, text in core_config.ui_info.descriptions_by_lang.items()
    ]
    ui_info["display_name"] = [
        {"text": text, "lang": lang_code}
        for lang_code, text in core_config.ui_info.displaynames_by_lang.items()
    ]
    ui_info["information_url"] = [
        {"text": text, "lang": lang_code}
        for lang_code, text in core_config.ui_info.information_urls_by_lang.items()
    ]
    ui_info["privacy_statement_url"] = [
        {"text": text, "lang": lang_code}
        for lang_code, text in core_config.ui_info.privacy_statement_urls_by_lang.items()
    ]

    ui_info["logo"] = list(core_config.ui_info.logos)  # type: ignore[arg-type]  # type is correct as it is checked at initialization of .logos, but mypy can't tell

    return {
        "allow_unsolicited": True,
        "authn_requests_signed": False,
        "digest_algorithm": DIGEST_SHA256,
        "endpoints": {
            "assertion_consumer_service": acs_endpoints,
        },
        # TODO: are the following two needed? which values?
        "force_authn": False,
        "name_id_format_allow_create": True,
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
        "ui_info": ui_info,
        "want_assertions_signed": False,
        "want_assertions_or_response_signed": True,
        "want_response_signed": False,
    }


# TODO: remove below this
def test() -> None:  # noqa: C901
    """Test."""
    from flask import current_app  # noqa: PLC0415

    from ..saml_config import config_dict as hardcoded_config  # noqa: PLC0415
    from .pysaml2_core import Pysaml2ConfigCore  # noqa: PLC0415

    config_core = Pysaml2ConfigCore(
        flask_config={
            "EDUGAIN_COC_COMPLIANT": True,
            "EDUGAIN_REFEDS_COMPLIANT": True,
            "EDUGAIN_CONTACT_SECURITY_EMAIL": "repository-support@tugraz.at",
            "EDUGAIN_CONTACT_SECURITY_GIVEN_NAME": "Security",
            "EDUGAIN_CONTACT_SECURITY_SUR_NAME": "Contact",
            "EDUGAIN_CONTACT_SUPPORT_EMAIL": "repository-support@tugraz.at",
            "EDUGAIN_CONTACT_SUPPORT_GIVEN_NAME": "Technical",
            "EDUGAIN_CONTACT_SUPPORT_SUR_NAME": "Support",
            "EDUGAIN_ENCRYPTION_CERT": "pki/mycert.pem",
            "EDUGAIN_ENCRYPTION_KEY": "pki/mykey.pem",
            "EDUGAIN_SIGNING_CERT": "pki/mycert.pem",
            "EDUGAIN_SIGNING_KEY": "pki/mykey.pem",
            "EDUGAIN_ORG_DISPLAYNAMES_BY_LANG": {
                "en": "Graz University of Technology",
                "de": "Technische Universität Graz",
            },
            "EDUGAIN_ORG_NAMES_BY_LANG": {
                "en": "Graz University of Technology",
                "de": "Technische Universität Graz",
            },
            "EDUGAIN_ORG_URLS_BY_LANG": {
                "en": "https://www.tugraz.at/en/home",
                "de": "https://www.tugraz.at/home",
            },
            "EDUGAIN_MAIN_SERVER_DOMAIN": "https://repository.tugraz.at",
            "EDUGAIN_OTHER_SERVER_DOMAINS": [
                "https://127.0.0.1:5000",
                "https://localhost:5000",
                "https://invenio01-demo.tugraz.at",
            ],
            "EDUGAIN_SERVICE_DESCRIPTION_EN": "The TU Graz Repository is a platform of Graz University of Technology where scientific papers, research data and open educational resources are collected, stored and made publicly available on a long-term basis. It serves to promote open access, open educational resources and participation in open science activities.",
            "EDUGAIN_SERVICE_NAME_EN": "TU Graz Repository",
            "EDUGAIN_UIINFO_DESCRIPTIONS_BY_LANG": {
                "en": "The TU Graz Repository is a platform of Graz University of Technology where scientific papers, research data and open educational resources are collected, stored and made publicly available on a long-term basis. It serves to promote open access, open educational resources and participation in open science activities.",
                "de": "Das TU Graz Repository ist eine Plattform der Technischen Universität Graz, auf der wissenschaftliche Arbeiten, Forschungsdaten und offene Bildungsressourcen nachhaltig gesammelt, gespeichert und öffentlich zugänglich gemacht werden. Es dient der Förderung von Open Access, Open Educational Resources und der Teilhabe an Open-Science-Aktivitäten.",
            },
            "EDUGAIN_UIINFO_DISPLAYNAMES_BY_LANG": {
                "en": "TU Graz Repository",
                "de": "TU Graz Repository",
            },
            "EDUGAIN_UIINFO_LOGOS": [
                {
                    "height": "177",
                    "width": "177",
                    "text": "https://repository.tugraz.at/static/images/library_logo.png",
                },
            ],
            "EDUGAIN_UIINFO_PRIVACY_URLS_BY_LANG": {
                "en": "https://repository.tugraz.at/static/documents/TUGraz_Repository_General_Data_Protection_Rights_en.pdf",
                "de": "https://repository.tugraz.at/static/documents/TUGraz_Repository_General_Data_Protection_Rights_de.pdf",
            },
            "EDUGAIN_UIINFO_INFO_URLS_BY_LANG": {
                "en": "https://repository.tugraz.at/",
                "de": "https://repository.tugraz.at/",
            },
        },
    )
    computed_config = build_pysaml2_config(current_app, config_core)

    def pp(path: tuple) -> str:
        """PP."""
        return ".".join(str(i) for i in path)

    def walk(  # noqa: C901, PLR0912
        computed: TupleJSON,
        hard_coded: TupleJSON,
        path: tuple = (),
    ) -> Exception | None:
        if type(computed) is not type(hard_coded):
            return TypeError(
                f"{pp(path)}\ntype-mismatch: computed {type(computed)!r}, hard-coded: {type(hard_coded)}",
            )

        errors: list[Exception] = []
        if isinstance(computed, dict) and isinstance(hard_coded, dict):
            extra_keys = sorted(set(computed) - set(hard_coded))
            missing_keys = sorted(set(hard_coded) - set(computed))
            common_keys = sorted(set(computed) & set(hard_coded))
            if extra_keys:
                errors.append(KeyError(f"extra-keys {extra_keys}"))
            if missing_keys:
                errors.append(KeyError(f"missing-keys {missing_keys}"))
            for key in common_keys:
                sub_error = walk(computed[key], hard_coded[key], (*path, key))
                if sub_error:
                    errors.append(sub_error)
            if errors:
                return ExceptionGroup(pp(path), errors)
        elif isinstance(computed, (list, tuple)) and isinstance(
            hard_coded,
            (list, tuple),
        ):
            if len(computed) != len(hard_coded):
                errors.append(
                    IndexError(
                        f"{pp(path)}: len-differs: computed {len(computed)}, hard-coded {len(hard_coded)}",
                    ),
                )
            for i, (c, h) in enumerate(zip(computed, hard_coded, strict=False)):
                error = walk(c, h, (*path, i))
                if error:
                    errors.append(error)
            if errors:
                return ExceptionGroup(pp(path), errors)
        elif isinstance(computed, (str, bool, type(None))):
            if computed != hard_coded:
                return ValueError(
                    f"{pp(path)}\nvalue-mismatch: computed {computed!r}, hard-coded: {hard_coded}",
                )

        return None

    error = walk(computed_config, hardcoded_config)
    if error:
        raise error
