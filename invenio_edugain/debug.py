"""Debug utils."""

from datetime import datetime, timezone


def log(*args, **kwargs) -> None:
    """Log to file."""
    with open(
        "/home/obersteiner/repositories/martinobersteiner/invenio-edugain/invenio_edugain/log",
        "a",
    ) as buf:
        print(datetime.now(tz=timezone.utc).isoformat(), *args, file=buf, **kwargs)
