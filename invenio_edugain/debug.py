"""Debug utils."""

from collections.abc import Callable, Mapping
from functools import wraps
from logging import LogRecord, StreamHandler, getLogger
from traceback import format_exception

from lxml import etree

logger = getLogger("saml2.edugain")  # create sub-logger of root-logger 'saml2'


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
