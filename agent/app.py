from flask import Flask, request, jsonify
import json, datetime, os
from agent_core import analyze_with_agent

app = Flask(__name__)
REPORT_FILE = "reports.jsonl"

@app.route('/ingest', methods=['POST'])
def ingest():
    """
    Receives raw log data from the collector.
    """
    # The Collector sends the log line inside a JSON payload.
    data = request.get_json(force=True)
    raw = data.get('raw', '')
    
    # CRITICAL FIX: The collector sometimes wraps the log line in a list or dict.
    # This block converts 'raw' back into a single string for parsing.
    if isinstance(raw, dict) or isinstance(raw, list):
        # Dump the structure to a string if it's a dict/list
        raw_str = json.dumps(raw) 
    else:
        # Otherwise, ensure it's a string
        raw_str = str(raw) 

    event = {
        "raw": raw_str,
        "host": data.get('host','unknown'),
        # Using datetime.datetime.now(datetime.UTC) for modern compatibility
        "received_at": data.get('received_at', datetime.datetime.now(datetime.timezone.utc).isoformat())
    }

    # Basic parsing to extract IPs from the raw log line (now guaranteed to be a string)
    event_struct = parse_pfirewall_line(event["raw"])
    event.update(event_struct)

    # Call the Agent Core for analysis and potential execution
    plan = analyze_with_agent(event)

    # Append to report log
    with open(REPORT_FILE,"a", encoding="utf-8") as f:
        f.write(json.dumps({"event":event,"plan":plan}) + "\n")

    return jsonify(plan), 200

def parse_pfirewall_line(line):
    """
    Simple parser to extract Source and Destination IPs.
    """
    # 'line' is now guaranteed to be a string, so .split() works.
    parts = line.split()
    out = {}
    try:
        # Detect IPs in the line
        ip_count = 0
        for p in parts:
            # Simple IP validation check
            if p.count('.') == 3 and all(x.isdigit() and 0<=int(x)<=255 for x in p.split('.')):
                if ip_count == 0:
                    out["src_ip"] = p
                    ip_count += 1
                elif ip_count == 1:
                    out["dst_ip"] = p
                    ip_count += 1
    except Exception:
        # Fails silently if parsing is impossible
        pass
    return out

if __name__ == '__main__':
    # Import datetime.timezone here to resolve the DeprecationWarning in the main file
    import datetime
    
    port = int(os.environ.get("PORT", 5000))
    print(f"Flask Agent running on 127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=True, use_reloader=False)
