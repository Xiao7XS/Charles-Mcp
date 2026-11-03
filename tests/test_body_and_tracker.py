"""Body rendering (protobuf, gRPC, multipart) and the incremental session tracker."""

from __future__ import annotations

import json

from charles5_mcp.session import parse_bytes
from charles5_mcp.session.body import render_body
from charles5_mcp.session.model import Message
from charles5_mcp.session.protobuf import decode_raw
from charles5_mcp.traffic.tracker import SessionTracker
from tests.conftest import make_txn


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number: int, wire: int, payload: bytes) -> bytes:
    return _varint((number << 3) | wire) + payload


def _protobuf_sample() -> bytes:
    nested = _field(1, 0, _varint(7)) + _field(2, 2, _varint(3) + b"abc")
    return (
        _field(1, 0, _varint(150))
        + _field(2, 2, _varint(5) + b"hello")
        + _field(3, 2, _varint(len(nested)) + nested)
    )


def test_schemaless_protobuf():
    fields = decode_raw(_protobuf_sample())
    assert fields[0] == {"field": 1, "type": "varint", "value": 150}
    assert fields[1]["value"] == "hello"
    assert fields[2]["message"][1]["value"] == "abc"


def test_grpc_frames_are_split_and_decoded():
    message = _protobuf_sample()
    frame = b"\x00" + len(message).to_bytes(4, "big") + message
    view = render_body(
        Message(headers=[("content-type", "application/grpc")], body=frame * 2, body_decoded=True)
    )
    assert view.kind == "grpc"
    assert len(view.parsed) == 2 and view.parsed[0]["fields"][0]["value"] == 150


def test_multipart_summary():
    body = (
        '--XyZ\r\nContent-Disposition: form-data; name="user"\r\n\r\nalice\r\n'
        '--XyZ\r\nContent-Disposition: form-data; name="file"; filename="a.png"\r\n'
        "Content-Type: image/png\r\n\r\n\x89PNG\r\n--XyZ--\r\n"
    )
    message = Message(
        headers=[("Content-Type", "multipart/form-data; boundary=XyZ")],
        body=body.encode(),
        body_decoded=True,
    )
    view = render_body(message)
    assert view.kind == "multipart"
    assert view.parts[0]["name"] == "user" and view.parts[0]["value"] == "alice"
    assert view.parts[1]["filename"] == "a.png"


def _session(*txns):
    return parse_bytes(json.dumps(list(txns)).encode())


def test_tracker_updates_in_flight_entries_in_place():
    pending = make_txn("/slow", status=None, charles_status="RECEIVING_RESPONSE", end=None)
    tracker = SessionTracker("t")
    first = tracker.ingest(_session(pending))
    assert len(first.new_ids) == 1 and not tracker.slice(0)[0].txn.is_complete

    done = dict(pending, status="COMPLETE")
    done["response"] = dict(pending["response"], status=200)
    done["times"] = dict(pending["times"], end=pending["times"]["start"])
    second = tracker.ingest(_session(done))
    assert second.new_ids == [] and second.updated_ids == first.new_ids
    assert tracker.total == 1 and tracker.slice(0)[0].txn.response_status == 200


def test_tracker_keeps_identical_requests_apart_and_detects_reset():
    a = make_txn("/same")
    b = dict(a)  # identical identity: same start, same client port
    tracker = SessionTracker("t")
    assert len(tracker.ingest(_session(a, b)).new_ids) == 2
    # Charles session cleared, new traffic arrives
    update = tracker.ingest(_session(make_txn("/after-clear")))
    assert update.reset_detected and len(update.new_ids) == 1
    assert tracker.total == 3


def test_tracker_baseline_and_cap():
    old = make_txn("/old")
    tracker = SessionTracker("t", max_entries=2)
    tracker.set_baseline(_session(old), include_existing=False)
    news = [make_txn(f"/n{i}") for i in range(3)]
    update = tracker.ingest(_session(old, *news))
    assert len(update.new_ids) == 2 and update.dropped == 1  # /n0 trimmed in the same poll
    assert [e.txn.path for e in tracker.slice(0)] == ["/n1", "/n2"]
    assert tracker.total == 3 and tracker.offset == 1


def test_tracker_trim_does_not_readmit_entries_still_in_charles():
    txns = [make_txn(f"/t{i}") for i in range(5)]
    tracker = SessionTracker("t", max_entries=3)
    first = tracker.ingest(_session(*txns))
    assert len(first.new_ids) == 3 and tracker.offset == 2
    for _ in range(3):
        again = tracker.ingest(_session(*txns))
        assert again.new_ids == [] and again.dropped == 0
    assert tracker.total == 5 and [e.txn.path for e in tracker.slice(0)] == ["/t2", "/t3", "/t4"]


def test_tracker_churn_is_not_a_reset():
    a, b, c, d = (make_txn(f"/c{i}") for i in range(4))
    tracker = SessionTracker("t")
    tracker.ingest(_session(a, b, c))
    update = tracker.ingest(_session(c, d))  # Charles dropped a, b; d arrived
    assert not update.reset_detected and len(update.new_ids) == 1
    update = tracker.ingest(_session(d))  # user deleted c
    assert not update.reset_detected


def test_unknown_or_bogus_charsets_fall_back_to_utf8():
    txn = make_txn("/cs", response_type="text/html; charset=x-weird", response_text="héllo")
    txn["request"]["charset"] = 7
    txn["query"] = 5
    txn["status"] = 3
    txn["totalSize"] = "1e400"
    parsed = _session(txn)[0]
    assert render_body(parsed.response).text == "héllo"
    assert parsed.query == "5" and parsed.total_size is None and parsed.identity_key()
