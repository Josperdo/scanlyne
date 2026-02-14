# Scanlyne

A Flask-based web interface for running nmap scans, viewing results, and comparing scans to detect network changes.

## Setup

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

pip install -r requirements.txt
python app.py
```

Requires [nmap](https://nmap.org/download.html) installed and available in PATH.

## Project Structure

```
├── app.py              # Flask app factory (done)
├── config.py           # App configuration (done)
├── models.py           # SQLAlchemy models: Scan, Host, Port (done)
├── parser.py           # Nmap XML output parser (stub)
├── scanner.py          # Nmap subprocess runner with input validation (stub)
├── diff.py             # Scan comparison engine (stub)
├── blueprints/
│   ├── scan.py         # Routes: scan form + execution (stub)
│   ├── results.py      # Routes: scan history + detail view (stub)
│   └── compare.py      # Routes: scan diff selection + display (stub)
├── templates/          # Jinja2 templates (done)
├── static/
│   ├── css/style.css   # Stylesheet (done)
│   └── js/main.js      # Client-side validation + interactivity (stub)
└── scans/              # Nmap XML output storage (runtime)
```

## Implementation Roadmap

### Phase 1: Flask Basics — Query & Render

- [ ] `blueprints/results.py` — `list_scans()`: query all scans, render the list template
- [ ] `blueprints/results.py` — `detail()`: look up scan by ID, handle 404, render detail template

### Phase 2: XML Parsing

- [ ] `parser.py` — file existence check + `FileNotFoundError`
- [ ] `parser.py` — XML parsing with `ET.parse()` + `ParseError` handling
- [ ] `parser.py` — extract scan-level metadata from root element attributes
- [ ] `parser.py` — extract host data: address, hostname, status
- [ ] `parser.py` — extract port data: number, protocol, state, service, version
- [ ] `parser.py` — assemble and return the final structured dict

### Phase 3: Scan Execution (Security-Critical)

- [ ] `scanner.py` — populate `ALLOWED_FLAGS` set with safe nmap options
- [ ] `scanner.py` — write `TARGET_PATTERN` regex (block shell metacharacters)
- [ ] `scanner.py` — implement `validate_target()` (empty check, length check, pattern match)
- [ ] `scanner.py` — implement `validate_flags()` (tokenize with `shlex.split`, check whitelist)
- [ ] `scanner.py` — implement `run_scan()` (build command list, subprocess.run, error handling)

### Phase 4: Scan Comparison

- [ ] `diff.py` — `compare_scans()`: build address-keyed dicts, set operations for new/removed hosts
- [ ] `diff.py` — `_compare_host_ports()`: port-level diff with (port, protocol) tuple keys
- [ ] `diff.py` — detect service/state changes on shared ports

### Phase 5: Blueprint Route Logic

- [ ] `blueprints/scan.py` — `start_scan()`: read form data, validate, create Scan record
- [ ] `blueprints/scan.py` — `start_scan()`: call `run_scan()`, handle success/failure
- [ ] `blueprints/scan.py` — `_store_parsed_results()`: persist hosts and ports to DB
- [ ] `blueprints/compare.py` — `select()`: query completed scans, render selection form
- [ ] `blueprints/compare.py` — `run_diff()`: validate inputs, parse XMLs, compare, render diff

### Phase 6: Client-Side JavaScript

- [ ] `static/js/main.js` — `initScanForm()`: validate target field on submit
- [ ] `static/js/main.js` — `initCompareForm()`: ensure two different scans are selected
- [ ] `static/js/main.js` — `initFlashDismiss()`: click-to-dismiss flash messages
- [ ] `static/js/main.js` — `showValidationError()`: display error messages near inputs

### Phase 7: Polish & Verification

- [ ] App starts without import errors (`python app.py`)
- [ ] Database creates on first run
- [ ] Scan form submits and triggers nmap
- [ ] Results page shows scan history and detail views
- [ ] Compare page shows differences between two scans
- [ ] Client-side validation blocks bad inputs before server round-trip

## Security Considerations

- Scan targets are validated against a whitelist regex — no shell metacharacters allowed
- Nmap flags are checked against an explicit allowlist — arbitrary flags like `--script` are blocked
- `subprocess.run()` is called without `shell=True` to prevent command injection
- Client-side validation is defense-in-depth only — all validation is duplicated server-side
- `SECRET_KEY` should be set via environment variable in production

## Known Limitations

- Scans run synchronously (the request blocks until nmap finishes)
- No authentication — anyone with access to the server can run scans
- No export functionality yet (CSV, JSON, PDF)
