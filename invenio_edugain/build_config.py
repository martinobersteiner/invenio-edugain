# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Utils to build a pysaml2 config."""
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, NamedTuple, Self

from flask import Flask


def deco[**P, R](func: Callable[P, R]) -> Callable:
    def field_from(config_key: str, *args: P.args, **kwargs: P.kwargs) -> R:
        """Construct a field that has a corresponding flask-app config-var."""
        if not kwargs.get("metadata"):
            kwargs["metadata"] = {}
        kwargs["metadata"]["config_key"] = config_key
        return func(*args, **kwargs)

    return field_from


field_from = deco(field)

from typing import ParamSpec

P = ParamSpec("P")


def f(x: int, y: int) -> int:
    """F."""
    return x + y


g: Callable[P, int] = f


class ResultExceptionsTuple(NamedTuple):
    """Holds result and exceptions."""

    result: dict[str, Any]
    exceptions: list[Exception]


# TODO: consider making .config_key_by_name class-vars
# TODO: `dataclass`es dont type-check..., use marshmallow instead?
# TODO: if bash env-vars are to work, strings must be parsed as json sometimes...
@dataclass
class Pysaml2ConfigABC(ABC):
    """Base class for `Pysaml2Config...` classes."""

    def __post_init__(self) -> None:
        """Check types post-initialization."""
        self_fields = self.__dataclass_fields__
        exceptions = []
        for field_name, field in self_fields.items():
            value = getattr(self, field_name)
            if not isinstance(value, field.type):
                msg = ""  # TODO
                exceptions.append(TypeError(msg))

        if exceptions:
            msg = ""  # TODO
            raise ExceptionGroup(msg, exceptions)

    @classmethod
    def parse_from_flask_config(cls, flask_config: Mapping) -> ResultExceptionsTuple:
        """Read and type-coerce values from `flask_config` into `result`.

        Uses cls.config_key_by_name to know which key to read from/write to.
        Keeps track of any exception happening when parsing.
        """
        fields = cls.__dataclass_fields__
        if fields.keys() != cls.config_key_by_name.keys():
            raise  # TODO: add to exceptions instead? raise on class-creation instead?

        result = {}
        exceptions: list[Exception] = []
        for name, config_key in cls.config_key_by_name.items():
            if config_key not in flask_config:
                msg = f"{config_key} is missing from app.config"
                exceptions.append(KeyError(msg))
                continue

            value = flask_config[config_key]
            field_type: type = fields[name].type  # TODO: guard against failing
            try:
                # try to coerce to correct type
                value = field_type(value)
            except Exception as exc:  # noqa: BLE001
                exc.add_note(
                    f"note: occured when instantiating {field_type!r} for {config_key!r}",
                )
                exceptions.append(exc)
                continue

            result[name] = value

        return ResultExceptionsTuple(result, exceptions)

    # TODO: classproperty how?
    @classmethod
    @property
    @abstractmethod
    def config_key_by_name(cls) -> dict:
        """Abstract class property."""

    @classmethod
    @abstractmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Abstract method."""


@dataclass
class Pysaml2ConfigEntityCategories(Pysaml2ConfigABC):
    """Holds entity-categories information for pysaml2 config."""

    coc: bool  # claims compliance with Geant CoC
    refeds: bool  # claims compliance with REFEDS research and scholarship

    config_key_by_name = {
        "coc": "EDUGAIN_COC_COMPLIANT",
        "refeds": "EDUGAIN_REFEDS_COMPLIANT",
    }

    @classmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Create from flask app."""
        result, exceptions = cls.parse_from_flask_config(app.config)
        if exceptions:
            msg = "entity-categories related issue"
            raise ExceptionGroup(msg, exceptions)

        return cls(**result)


@dataclass
class Pysaml2ConfigCryptographicCredentials(Pysaml2ConfigABC):
    """Holds cryptograhic credential related fields for pysaml2 config."""

    encryption_cert_filepath: Path
    encryption_key_filepath: Path
    signing_cert_filepath: Path
    signing_key_filepath: Path

    @classmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Create from flask app."""
        res = {}  # to be result
        config_key_by_name = {
            "encryption_cert_filepath": "EDUGAIN_ENCRYPTION_CERT",
            "encryption_key_filepath": "EDUGAIN_ENCRYPTION_KEY",
            "signing_cert_filepath": "EDUGAIN_SIGNING_CERT",
            "signing_key_filepath": "EDUGAIN_SIGNING_KEY",
        }
        for name, config_key in config_key_by_name.items():
            res[name] = app.config.get(config_key)

        exceptions: list[Exception] = []
        for name, value in list(res.items()):
            if value is None:
                msg = f"{config_key_by_name[name]!r} is missing from app.config"
                exceptions.append(KeyError(msg))
                continue

            try:
                res[name] = path = Path(value)
            except Exception as exc:  # noqa: BLE001
                exc.add_note(
                    f"note: occured when instantiating pathlib.Path for {config_key_by_name[name]!r}",
                )
                exceptions.append(exc)
                continue

            if not path.is_file():
                msg = f"no file exists at {value!r}"
                exceptions.append(FileNotFoundError(msg))

        if exceptions:
            msg = "MUST set these config-vars to existing file-paths"
            raise ExceptionGroup(msg, exceptions)

        return cls(**res)  # type: ignore[arg-type]


@dataclass
class Pysaml2ConfigOrganization(Pysaml2ConfigABC):
    """Holds info related to the organization running the SP for pysaml2 config."""

    org_displaynames_by_lang: dict[str, str]
    org_names_by_lang: dict[str, str]
    org_urls_by_lang: dict[str, str]

    @classmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Create from flask app."""
        res = {}  # to be result
        config_key_by_name = {
            "org_displaynames_by_lang": "EDUGAIN_ORG_DISPLAYNAMES_BY_LANG",
            "org_names_by_lang": "EDUGAIN_ORG_NAMES_BY_LANG",
            "org_urls_by_lang": "EDUGAIN_ORG_URLS_BY_LANG",
        }
        for name, config_key in config_key_by_name.items():
            res[name] = app.config.get(config_key)

        exceptions: list[Exception] = []
        for name, value in res.items():
            if value is None:
                msg = f"{config_key_by_name[name]!r} is missing from app.config"
                exceptions.append(KeyError(msg))
                continue
            if (
                not isinstance(value, dict)
                or any(not isinstance(key, str) for key in value)
                or any(not isinstance(v, dict) for v in value.values())
            ):
                msg = f"value at app.config[{config_key_by_name[name]!r}] must be dict[str, str]"
                exceptions.append(TypeError(msg))

        if exceptions:
            msg = "Organization-related issues"
            raise ExceptionGroup(msg, exceptions)
        return cls(**res)  # type: ignore[arg-type]


@dataclass
class Pysaml2ConfigUIInfo(Pysaml2ConfigABC):
    """Holds info shown to users about this SP, used for creating a pysaml2 config."""

    descriptions_by_lang: dict[str, str]
    displaynames_by_lang: dict[str, str]
    information_urls_by_lang: dict[str, str]
    logos: list[dict[str, str]]
    privacy_statement_urls_by_lang: dict[str, str]

    @classmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Create from flask app."""
        return cls()


@dataclass
class Pysaml2ConfigContactEmails(Pysaml2ConfigABC):
    """Holds info on emails to be contacted when issues arise, used for creating a pysaml2 config."""

    security_contact: str
    technical_support: str

    @classmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Create from flask app."""
        return cls()


@dataclass
class Pysaml2ConfigProvidedService(Pysaml2ConfigABC):
    """Holds info on the provided service, used for creating a pysaml2 config."""

    # NOTE: due to internal represantation used by pysaml2, only "en"glish names are givable here
    description_en: str
    name_en: str

    @classmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Create from flask app."""
        return cls()


@dataclass
class Pysaml2ConfigCore(Pysaml2ConfigABC):  # TODO: rename
    """Holds those pysaml2 config fields that MUST be user-provided.

    e.g. organization-name MUST be provided (as we cannot possibly know it), but timeout can be left at default
    """

    category: Pysaml2ConfigEntityCategories
    credentials: Pysaml2ConfigCryptographicCredentials
    email: Pysaml2ConfigContactEmails
    org: Pysaml2ConfigOrganization
    served_on_servers: list[
        str
    ]  # servers this SP is served on, e.g. ["prod.org", "test.org"]
    service: Pysaml2ConfigProvidedService
    uiinfo: Pysaml2ConfigUIInfo

    @classmethod
    def from_flask_app(cls, app: Flask) -> Self:
        """Create from flask app.

        This mostly takes info from `app.config`.
        Raises ExceptionGroup of all misconfigurations, if any.
        """
        res = {}  # to be result

        sub_builders = {
            "category": Pysaml2ConfigEntityCategories,
            "credentials": Pysaml2ConfigCryptographicCredentials,
            "email": Pysaml2ConfigContactEmails,
            "org": Pysaml2ConfigOrganization,
            "service": Pysaml2ConfigProvidedService,
            "uiinfo": Pysaml2ConfigUIInfo,
        }
        exceptions = []
        for name, builder_cls in sub_builders.items():
            try:
                res[name] = builder_cls.from_flask_app(app)  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001
                exceptions.append(exc)

        if exceptions:
            msg = (
                "errors when trying to create pysaml2 config from app.config\n"
                "either create configuration via code (see docs) or fix these errors"
            )
            raise ExceptionGroup(msg, exceptions)

        return cls(**res)
