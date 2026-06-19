import json
import logging

from orchestrasecai.observability.context import bind_context, clear_context
from orchestrasecai.observability.logging import configure_logging, get_logger


def test_correlation_ids_on_every_log_line(caplog):
    caplog.set_level(logging.INFO)
    configure_logging("test-service")
    bind_context(request_id="req-1", org_id="org-1", scan_id="scan-1")
    logger = get_logger("test")
    logger.info("test_event", extra_field="value")
    clear_context()

    payload = json.loads(caplog.records[-1].message)
    assert payload["request_id"] == "req-1"
    assert payload["org_id"] == "org-1"
    assert payload["scan_id"] == "scan-1"
    assert payload["event"] == "test_event"
    assert payload["extra_field"] == "value"


def test_unset_correlation_ids_are_null(caplog):
    caplog.set_level(logging.INFO)
    configure_logging("test-service")
    clear_context()
    logger = get_logger("test")
    logger.info("bare_event")

    payload = json.loads(caplog.records[-1].message)
    assert payload["request_id"] is None
    assert payload["org_id"] is None
    assert payload["scan_id"] is None
