# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Command line interface for invenio-edugain."""

import validators
from click import argument, group, secho, style
from flask.cli import with_appcontext
from invenio_db import db
from saml2.config import Config
from saml2.mdstore import MetadataStore

from . import ingest
from .models import IdPData


# TODO: better docstrings in commands with examples and longer explanations
@group()
def edugain() -> None:
    """CLI-group for `invenio edugain` commands."""


@edugain.command("ingest")
@argument("file_or_url")
@with_appcontext
def ingest_idps(file_or_url: str) -> None:
    """Import idp-configurations from file/url."""
    mds = MetadataStore(None, Config())
    if validators.url(file_or_url):
        mds.load("remote", url=file_or_url)
    else:
        mds.load("local", file_or_url)

    import_item = ingest.from_mdstore(mds)
    secho(
        f"Successfully imported idp-settings from {file_or_url!r}\n"
        f"- {len(import_item.added_idp_ids)} added\n"
        f"- {len(import_item.updated_idp_ids)} updated\n"
        f"- {len(import_item.unchanged_idp_ids)} already up-to-date",
        fg="green",
    )


@edugain.command("list")
@with_appcontext
def list_idps() -> None:
    """List currently persisted idp-settings."""
    # TODO: output json instead if sys.stdout.isatty()
    for idp_data in db.session.scalars(db.select(IdPData).order_by(IdPData.id)):
        enabled = idp_data.enabled
        discoverable = idp_data.discoverable
        enabled_str = style("O" if enabled else "X", fg="green" if enabled else "red")
        discoverable_str = style(
            "O" if discoverable else "X",
            fg="green" if discoverable else "red",
        )
        idp_id_str = style(idp_data.id, fg="cyan")
        secho(enabled_str + " " + discoverable_str + " " + idp_id_str)


@edugain.command()
def init() -> None:
    """Initialize db-tables."""
    secho("Not implemented yet", fg="red")


@edugain.command()
def enable_all() -> None:
    """Enable all imported IdPs."""
    idps_data = list(db.session.execute(db.select(IdPData)))
    for idp_data in idps_data:
        idp_data[0].enabled = True
    db.session.commit()
