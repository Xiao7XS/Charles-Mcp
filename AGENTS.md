# AGENTS.md — rules for agents using charles5-mcp

## Planes and ids

| Plane | Start with | Id to keep |
| --- | --- | --- |
| live | `start_live_capture` | `capture_id` (`cap-…`) |
| history | `list_recordings` | `recording_path` |
| reverse | `reverse_import_session` / `reverse_start_live_analysis` | reverse `capture_id` (`rcap-…`), `live_session_id` (`rlive-…`) |

Never mix ids across planes. Entry ids from one plane do not work in another.

## Defaults

1. For "what is the app doing now", use the live plane. Use history only when the user names a saved file.
2. Unsure? Call `charles_status` and follow `recommended_next_action`.
3. Never pass `reset_session=true` unless the user explicitly asks to clear Charles' session.

## Token budget

1. Start with `group_capture_analysis` or `get_capture_analysis_stats`.
2. Then `query_live_capture_entries` / `analyze_recorded_traffic` with small `max_items`.
3. Use `get_traffic_entry_detail` for one confirmed entry; keep `include_full_body=false` unless needed.

## Cursors

`read_*` consumes (advances the cursor); `peek_*` does not. `query_*` never moves cursors.

## Reverse workflow

1. Narrow with `reverse_query_entries`, or run `reverse_analyze_live_*_flow` / `reverse_analyze_capture`.
2. Read `summary` and `next` before the rest of a workflow result.
3. `reverse_discover_signature_candidates` labels fields; only `reverse_run_mutation_plan`
   proves which ones the server checks (`enforced` / `not_enforced`).
4. Replays send real traffic to the target. Only replay systems the user is authorised to test.
   If the control replay fails, the request is time-bound or single-use: capture it again
   and run the plan immediately.

## Charles behaviour to keep in mind

- Charles can only export the session it is **currently recording**. If recording is off,
  exports fail with "not recording"; starting recording opens a new, empty session. Earlier
  sessions must be saved in Charles and opened as files.
- If a result warns `charles_records_its_own_web_interface`, tell the user to add
  `control.charles` under Proxy > Recording Settings > Exclude before polling further;
  otherwise every poll makes the session grow exponentially.
- Use `get_charles_controls` before `throttling` to see the real preset names.
