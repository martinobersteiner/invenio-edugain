# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Graz University of Technology.
#
# invenio-edugain is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Utils for invenio-edugain."""

from typing import Any

from invenio_db import db
from saml2.mdstore import InMemoryMetaData
from sqlalchemy import select, true

from .models import IdPData


# TODO: cache, same cache as below
def get_idp_data_dict() -> dict:
    """Get from db a dict of the IdP-data of *enabled* idps."""
    query = select(IdPData).where(IdPData.enabled == true())
    # TODO: following type is actually iterable[IdPData]
    idps_data: list[IdPData] = db.session.execute(query).scalars()

    return {
        idp_data.id: {
            "displayname": idp_data.displayname,
            "logo_url": idp_data.logo_url,
        }
        for idp_data in idps_data
    }


class MetaDataFlaskSQL(InMemoryMetaData):
    """Loads idp-settings from SQL-db.

    This is akin to saml2.mdstore.MetaDataMD, which loads from file rather than from db.
    """

    def __init__(
        self,
        attrc: tuple | None,
        __: str,  # metadata loaders must always take a second positional arg, which doubles as id in MDStore
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        """Init."""
        super().__init__(attrc, **kwargs)

    # TODO: load only passed idp-id?
    # TODO: cache, same cache as above
    # TODO: pass some positional arg that actually does something? e.g. `db`
    def load(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401, ARG002
        """Load."""
        for idp in db.session.scalars(
            db.select(IdPData).where(IdPData.enabled == true())
        ):
            self.entity[idp.id] = idp.settings
