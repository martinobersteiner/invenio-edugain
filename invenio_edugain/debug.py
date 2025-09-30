"""Debug utils."""

from collections.abc import Callable, Mapping
from functools import wraps
from logging import LogRecord, StreamHandler, getLogger
from traceback import format_exception
from typing import Any

from lxml import etree

logger = getLogger("invenio_edugain")


def log(*args: Any, **kwargs: Any) -> None:  # noqa: ANN401
    """Log messages compatibly with pysaml2 logging."""
    # NOTE: pysaml2 adds handler, so no need to add one here

    # pysaml2 disables loggers during its work, but we need logging during that
    was_disabled = logger.disabled
    logger.disabled = False

    logger.debug(*args, **kwargs)

    logger.disabled = was_disabled


class AuthnHandler(StreamHandler):
    """Filter and reformat AuthnReq: logs."""

    def handle(self, record: LogRecord) -> bool:
        """Handle."""
        if record.msg.startswith("AuthNReq: "):
            if record.args is None or isinstance(record.args, Mapping):
                return False
            xml = record.args[0]

            root = etree.fromstring(xml)
            pretty_xml = etree.tostring(root, pretty_print=True).decode("utf-8")

            record.args = (pretty_xml,)

        return super().handle(record)


def log_error[**P, T](func: Callable[P, T]) -> Callable[P, T]:
    """Log exception (if any) then re-raise."""

    @wraps(func)
    def decorated_func(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            msg = "\n".join(format_exception(e))
            logger.debug(msg)

            raise

    return decorated_func
