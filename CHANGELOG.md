# Changelog

## 1.2.0 — request and response bodies in every shape

Checked against a real Charles 5.2.2 session covering JSON (plain, gzip, br,
zstd, deflate, BOM, mislabelled), UTF-8 and GBK forms, multipart uploads with
images, raw binary uploads, protobuf, XML, chunked uploads, JSONP, SSE, images,
PDF, zip, 204 and 304, exported as JSON, XML, HAR and chlz
(`tests/fixtures/charles-5.2.2/formats.*`).

### Fixed
- Chinese text showed as mojibake when the body declared no charset: Charles
  writes such bodies decoded as ISO-8859-1 in its JSON and XML exports (XML
  also escapes C1 characters as `&#NNN;`). The original bytes are now restored.
- Text without a declared charset is decoded as UTF-8, then GB18030; a BOM is
  stripped, so BOM-prefixed JSON parses.
- multipart uploads containing images or other binary parts were shown as
  binary; they are now split at the byte level into named parts with filename,
  size, detected type and value/JSON.
- Images, PDF, zip, audio and video are recognised by their magic bytes even
  when sent as `application/octet-stream`.
- JSONP responses are parsed.
- HAR: url-encoded params honour the declared charset; multipart params keep
  filenames, Content-Type and base64 file contents.
- Reverse analysis and replay of url-encoded forms keep the declared charset
  (a GBK form was decoded as UTF-8 and re-encoded as UTF-8); form overrides
  keep untouched parameters byte for byte and refuse multipart/JSON bodies.
- A charset naming a non-text codec (`base64`, `zlib`, `idna` ...) made the
  whole session fail to load; such charsets now fall back to UTF-8/GB18030.
- Short magic signatures (`BM`, `ID3`) no longer turn text bodies such as
  `BMI=22&x=1` into images.
- multipart: delimiters only count at line starts, parts without headers keep
  their data, `name` is not confused with `filename`, unquoted and RFC 5987
  (`filename*=GBK'zh'...`) parameters are read.
- HAR multipart: case-insensitive `Boundary`, text uploads are not
  base64-decoded, quotes in names are escaped.
- Decompression is capped at 64 MB per body (gzip/deflate/br/zstd bombs) and
  `.chlz` members over 512 MB are not loaded; concatenated gzip members decode.
- `extract_entry_bodies` writes `entry.json` for WebSocket entries too.

### Added
- `get_traffic_entries`: full records (URL, decoded query parameters,
  request/response headers, decoded bodies with structured JSON, form fields
  and multipart parts) for chosen entries or every match of a filter, with
  paging, or written to a JSON Lines file.
- `extract_entry_bodies`: saves an entry's decoded bodies to files (images,
  downloads, each multipart part, WebSocket messages) plus `entry.json`.
- `query_params` in entry details.

## 1.1.0 — verified against a real Charles 5.2.2

Every Charles interaction was re-checked by running Charles 5.2.2 headless and
pushing a fixed set of requests through it. Exports in every format are kept in
`tests/fixtures/charles-5.2.2/`; `tests/live/` runs the server end to end
against a running Charles (opt-in, `CHARLES5_MCP_LIVE=1`).

### Fixed
- Binary bodies (protobuf, images, zstd, octet-stream) were dropped from live
  exports: Charles stores them as `{"encoding": "base64", "encoded": "…"}`.
- Bodies Charles keeps compressed (it does not decode zstd) are now decompressed;
  `.chlz` sidecars named `<n>-res-enc.*` are recognised as still encoded and the
  meta file's `bodyFile` is honoured.
- `EXCEPTION` (Charles' failure status) is treated as a completed error, not as
  an in-flight request.
- With recording stopped Charles answers export URLs with an HTML page; this is
  now reported as "not recording" instead of a parse error, `export_charles_session`
  no longer saves that page as a recording, and live captures keep their data.
- Charles records its own Web Interface traffic, and each recorded export
  contains the previous one, so sessions grow exponentially while polling. This
  is detected and reported with the fix (exclude `control.charles` in Recording
  Settings).
- Throttling presets are validated against Charles' own list (Charles accepts
  any name silently and has no 5G preset).
- HAR: charset-aware text bodies, base64 bodies kept encoded until decoded,
  multipart `params` rebuilt as a multipart body.
- XML: `contentEncoding`, timing/duration attributes, TLS info and declared sizes.
- 1xx (103 Early Hints) linking works regardless of export order.
- URLs and replays use the requested `port`, not `actualPort` (Map Remote).
- Files written by this server are importable by Charles (no `null` members).
- `charles_version` is read from Charles.app / `charles --version`.
- Workflows and signature discovery scan whole captures (previously the first
  2000 / 500 entries); endpoint peers are found in SQL.
- Replays sent through Charles carry an `X-Charles5-MCP-Replay` header and are
  kept out of reverse live analysis, so they are not mistaken for app traffic.
- Details of in-flight entries refresh once they complete, and live reads list
  `updated_entry_ids` for entries that finished after they were returned.
- Every list-returning tool fits a ~40k-character response budget (cursors only
  advance over what was returned); reverse detail/decode honour the body cap.
- Empty sessions exported by Charles (empty zip) load as 0 entries; HAR sizes;
  unknown capture ids error out; exports never overwrite existing files.

### Added
- `get_charles_controls`: throttling state and presets, on/off state of every tool.
- `convert_session_file`: `charles convert` with host/MIME/method/size filters.
- `export_charles_session` formats `csv` and `trace`.
- Reading `.trace`, `.saz` (Fiddler) and `.pcap` via the Charles CLI; `.chls` is
  converted to Charles JSON instead of XML.
- WebSocket message decoding (both directions, fragmentation, permessage-deflate,
  JSON/protobuf payloads) in details, previews, keyword search and reverse decode.

## 1.0.1
- A disabled Web Interface (HTTP 200 with an explanatory page) is no longer
  reported as connected.

## 1.0.0
- Rewrite of Charles-mcp for Charles 5.2.x with MCP SDK 1.x/2.x support.
