"""Debug utils."""

import logging
import sys
from datetime import datetime, timezone

from lxml import etree
from saml2.client import logger


class AuthnHandler(logging.StreamHandler):
    def handle(self, record):
        if record.msg.startswith("AuthNReq: "):
            xml = record.args[0]

            root = etree.fromstring(xml)
            pretty_xml = etree.tostring(root, pretty_print=True).decode("utf-8")

            record.args = (pretty_xml,)

        return super().handle(record)


logger.setLevel(logging.DEBUG)
logger.addHandler(AuthnHandler(sys.stderr))


def log(*args, **kwargs) -> None:
    """Log to file."""
    with open(
        "/home/obersteiner/repositories/martinobersteiner/invenio-edugain/invenio_edugain/log",
        "a",
    ) as buf:
        print(datetime.now(tz=timezone.utc).isoformat(), *args, file=buf, **kwargs)
