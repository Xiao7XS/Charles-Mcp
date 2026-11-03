"""Live, history and control tools end-to-end through the MCP layer."""

from __future__ import annotations

import json
import plistlib

import pytest

from charles5_mcp.compat import ToolError
from tests.conftest import make_txn


async def test_status_reports_version_and_recording(call, fake, app, tmp_path):
    # The Web Interface never reports a version; it is read from Charles.app's Info.plist.
    contents = tmp_path / "Charles.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "MacOS" / "Charles").write_text("")
    (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": "5.2.2"}))
    app.settings.charles_cli_path = str(contents / "MacOS" / "Charles")
    status = await call("charles_status")
    assert status["connected"] is True
    assert status["charles_version"] == "5.2.2"
    assert status["recording"] == "recording"
    assert status["throttling"] == "off"
    assert "start_live_capture" in status["recommended_next_action"]


async def test_status_explains_stopped_recording(call, fake):
    fake.recording = False
    status = await call("charles_status")
    assert status["recording"] == "stopped" and "not recording" in status["note"]


async def test_status_when_charles_is_down(call, fake):
    fake.reachable = False
    status = await call("charles_status")
    assert status["connected"] is False
    assert "Web Interface" in status["hint"]


async def test_wrong_credentials_surface_a_hint(call, fake):
    fake._auth = "Basic nope"
    with pytest.raises(ToolError) as info:
        await call("start_live_capture")
    assert "CHARLES_USER" in str(info.value)


async def test_live_capture_cursor_flow(call, fake):
    fake.add(make_txn("/before"))
    started = await call("start_live_capture")
    capture_id = started["capture_id"]
    assert started["baseline_entries_skipped"] == 1
    assert started["recording_started_by_server"] is False  # Charles was already recording
    assert "/session/clear" not in fake.calls  # never clears by default

    fake.add(
        make_txn("/api/a", response_json={"ok": 1}),
        make_txn("/img/logo.png", response_type="image/png", response_text="x"),
    )
    peek = await call("peek_live_capture", capture_id=capture_id)
    assert [i["path"] for i in peek["items"]] == ["/api/a", "/img/logo.png"]
    first = await call("read_live_capture", capture_id=capture_id)
    assert first["next_cursor"] == 2
    again = await call("read_live_capture", capture_id=capture_id)
    assert again["returned"] == 0

    fake.add(make_txn("/api/b", method="POST", status=500, response_json={"code": 500}))
    query = await call("query_live_capture_entries", capture_id=capture_id)
    paths = [i["path"] for i in query["items"]]
    assert "/img/logo.png" not in paths and set(paths) == {"/api/a", "/api/b"}
    assert query["filtered_out_by_preset"] == {"image": 1}

    errors = await call("query_live_capture_entries", capture_id=capture_id, preset="errors_only")
    assert [i["path"] for i in errors["items"]] == ["/api/b"]

    json_query = await call(
        "query_live_capture_entries", capture_id=capture_id, response_json_query="ok == `1`"
    )
    assert [i["path"] for i in json_query["items"]] == ["/api/a"]

    detail = await call(
        "get_traffic_entry_detail",
        entry_id=errors["items"][0]["entry_id"],
        capture_id=capture_id,
        include_full_body=True,
    )
    assert detail["status"] == 500 and detail["response"]["body"]["text"] == '{"code":500}'

    groups = await call(
        "group_capture_analysis",
        source="live",
        group_by="status",
        capture_id=capture_id,
        preset="all_http",
    )
    assert {g["value"] for g in groups["groups"]} == {"200", "500"}

    stopped = await call("stop_live_capture", capture_id=capture_id)
    assert stopped["status"] == "stopped" and stopped["recording_path"].endswith(".chlsj")
    assert fake.recording is True  # the user started recording, so it is left running

    history = await call(
        "analyze_recorded_traffic", recording_path=stopped["recording_path"], preset="all_http"
    )
    assert history["matched"] == 3
    entry = history["items"][0]["entry_id"]
    detail = await call("get_traffic_entry_detail", entry_id=entry)  # resolved without source/path
    assert detail["source"] == "history"


async def test_reset_session_only_when_asked(call, fake):
    fake.add(make_txn("/keep"))
    await call("start_live_capture", reset_session=True)
    assert "/session/clear" in fake.calls
    assert [t["path"] for t in fake.session if t["host"] != "control.charles"] == []


async def test_starting_a_stopped_recording_and_stopping_it_again(call, fake):
    fake.recording = False
    started = await call("start_live_capture")
    assert started["recording_started_by_server"] is True and fake.recording is True
    fake.add(make_txn("/new"))
    capture_id = started["capture_id"]
    assert [
        i["path"] for i in (await call("read_live_capture", capture_id=capture_id))["items"]
    ] == ["/new"]
    fake.recording = False  # user stops recording in Charles
    read = await call("read_live_capture", capture_id=capture_id)
    assert any("charles_not_recording" in w for w in read["warnings"])
    stopped = await call("stop_live_capture", capture_id=capture_id)
    assert stopped["total_entries"] == 1 and stopped["recording_path"]


async def test_export_while_not_recording_is_explained(call, fake):
    fake.recording = False
    with pytest.raises(ToolError) as info:
        await call("export_charles_session")
    assert "not recording" in str(info.value) and "File > Save Session" in str(info.value)


async def test_live_falls_back_to_xml_export(call, fake):
    fake.json_export_enabled = False
    capture = (await call("start_live_capture"))["capture_id"]
    fake.add(make_txn("/xml-only"))
    read = await call("read_live_capture", capture_id=capture)
    assert read["items"][0]["path"] == "/xml-only"


async def test_history_listing_snapshot_and_regex(call, fake, app):
    fake.add(
        make_txn("/api/login", method="POST", response_json={"token": "abc"}), make_txn("/api/me")
    )
    exported = await call("export_charles_session", name="sample")
    assert exported["format"] == "chlsj" and exported["size_bytes"] > 0
    listing = await call("list_recordings")
    assert listing["recordings"][0]["name"] == "sample.chlsj"
    snapshot = await call("get_recording_snapshot")
    assert snapshot["stats"]["classes"]["api"] == 2
    found = await call("query_recorded_traffic", keyword_regex="tok.n")
    assert [i["path"] for i in found["items"]] == ["/api/login"]
    with pytest.raises(ToolError):
        await call("query_recorded_traffic", keyword_regex="(unclosed")


async def test_throttling_validates_presets(call, fake):
    assert (await call("throttling", preset="3g"))["preset"] == "3G"
    assert fake.throttle_preset == "3G" and fake.throttle_active
    assert (await call("throttling", preset="56k"))["preset"] == "56 kbps Modem"
    with pytest.raises(ToolError) as info:
        await call("throttling", preset="5g")  # Charles 5.2.2 has no 5G preset
    assert "4G" in str(info.value)
    await call("throttling", preset="off")
    assert fake.throttle_active is False


async def test_controls_and_tool_toggles(call, fake):
    controls = await call("get_charles_controls")
    assert "100 Mbps Fibre" in controls["throttling"]["presets"]
    assert set(controls["tools"]) >= {"map-remote", "rewrite", "block-list", "allow-list"}
    assert controls["tools"]["map-remote"]["enabled"] is False
    toggled = await call("set_charles_tool", tool="map-remote", enabled=True)
    assert toggled == {"tool": "map-remote", "name": "Map remote", "enabled": True}
    assert (await call("get_charles_controls"))["tools"]["map-remote"]["enabled"] is True


async def test_reset_environment_requires_backup(call):
    result = await call("reset_environment", confirm=True)
    assert result["restored"] is False


async def test_unknown_capture_gives_hint(call):
    with pytest.raises(ToolError) as info:
        await call("read_live_capture", capture_id="cap-missing")
    assert "start_live_capture" in str(info.value)


def test_literal_choices_match_runtime_tables():
    from typing import get_args

    from charles5_mcp.charles.client import TOOL_SLUGS
    from charles5_mcp.control import EXPORT_FORMATS
    from charles5_mcp.server import CharlesToolName, ExportFormat, GroupKey
    from charles5_mcp.traffic.service import GROUP_KEYS

    assert set(get_args(CharlesToolName)) == set(TOOL_SLUGS)
    assert set(get_args(ExportFormat)) == set(EXPORT_FORMATS)
    assert set(get_args(GroupKey)) == set(GROUP_KEYS)


async def test_read_after_trim_never_loops(call, fake, app):
    app.settings.live_max_entries = 3
    capture_id = (await call("start_live_capture"))["capture_id"]
    fake.add(*[make_txn(f"/p{i}") for i in range(6)])
    seen = []
    for _ in range(4):
        read = await call("read_live_capture", capture_id=capture_id, limit=2)
        seen += [i["path"] for i in read.get("items", [])]
    assert seen == ["/p3", "/p4", "/p5"]


async def test_bad_charset_does_not_break_queries(call, fake):
    capture_id = (await call("start_live_capture"))["capture_id"]
    fake.add(make_txn("/x", response_type="text/html; charset=x-weird", response_text="<p>hi</p>"))
    result = await call("query_live_capture_entries", capture_id=capture_id, preset="all_http")
    assert result["matched"] == 1


async def test_jmespath_type_errors_are_non_matches(call, fake):
    capture_id = (await call("start_live_capture"))["capture_id"]
    fake.add(make_txn("/a", response_json={"data": 5}), make_txn("/b", response_json={"data": [1]}))
    result = await call(
        "query_live_capture_entries",
        capture_id=capture_id,
        response_json_query="length(data) > `0`",
    )
    assert [i["path"] for i in result["items"]] == ["/b"]


async def test_disabled_web_interface_is_not_reported_as_connected(call, fake):
    fake.web_interface_enabled = False
    status = await call("charles_status")
    assert status["connected"] is False
    assert "Web Interface is disabled" in status["error"]
    assert "Enable web interface" in status["hint"]
    with pytest.raises(ToolError) as info:
        await call("start_live_capture")
    assert "disabled" in str(info.value)


async def test_self_recording_is_flagged_until_excluded(call, fake):
    started = await call("start_live_capture")
    assert any("Recording Settings > Exclude" in w for w in started["warnings"])
    status = await call("charles_status")
    assert "control.charles" in status["warning"]

    fake.record_control_requests = (
        False  # user added control.charles to Recording Settings > Exclude
    )
    fake.session = [t for t in fake.session if t["host"] != "control.charles"]
    started = await call("start_live_capture")
    assert not any("Recording Settings" in w for w in started.get("warnings", []))


async def test_in_flight_entries_refresh_and_are_reported_when_done(call, fake):
    capture_id = (await call("start_live_capture"))["capture_id"]
    slow = make_txn("/slow", status=None, charles_status="RECEIVING_RESPONSE_BODY", end=None)
    fake.add(slow)
    first = await call("read_live_capture", capture_id=capture_id)
    entry_id = first["items"][0]["entry_id"]
    assert first["items"][0]["in_progress"] is True
    slow["status"] = "COMPLETE"
    slow["response"]["status"] = 200
    slow["times"]["end"] = slow["times"]["start"]
    detail = await call("get_traffic_entry_detail", entry_id=entry_id, capture_id=capture_id)
    assert detail["status"] == 200
    later = await call("read_live_capture", capture_id=capture_id)
    assert later["updated_entry_ids"] == [entry_id]


async def test_large_reads_stay_within_the_response_budget(call, fake):
    capture_id = (await call("start_live_capture"))["capture_id"]
    fake.add(*[make_txn(f"/api/item/{i}" + "x" * 200, response_json={"i": i}) for i in range(400)])
    read = await call("read_live_capture", capture_id=capture_id, limit=200)
    assert len(json.dumps(read)) < 45_000 and read["budget_trimmed"]["dropped"] > 0
    again = await call("read_live_capture", capture_id=capture_id, limit=200)
    assert again["cursor"] == read["next_cursor"]  # nothing skipped


async def test_empty_charles_archive_and_bad_size_filter(call, tmp_path):
    empty = tmp_path / "empty.chlz"
    empty.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    stats = await call("get_capture_analysis_stats", source="history", recording_path=str(empty))
    assert stats["entries"] == 0
    with pytest.raises(ToolError) as info:
        await call("convert_session_file", path=str(empty), max_response_size="abc")
    assert "max_response_size" in str(info.value)
