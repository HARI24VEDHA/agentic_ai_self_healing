import httpx
import json
import subprocess
import os
import datetime

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "llama3" # Use the model you confirmed works

def analyze_with_agent(event_data):
    """
    Analyzes the log data using the LLM and executes the firewall plan if provided.
    """
    src_ip = event_data.get("src_ip", "Unknown")
    
    # 1. LLM Prompt Construction
    prompt = f"""
    You are a cybersecurity expert firewall agent. Your task is to analyze a single firewall log event and determine 
    if an action is required.
    
    Log Event: {event_data['raw']}
    Source IP: {src_ip}
    
    If the log shows a 'DROP' action, or if it indicates malicious behavior (which this one does, as it's a DROP log), 
    you MUST generate a PowerShell execution plan.
    
    The plan MUST only contain a single JSON object with two keys:
    1. "action": MUST be either "Block" or "None". Since this is a DROP event, the action should be "Block".
    2. "source_ip": MUST be the source IP to block ({src_ip}).
    
    Example response structure for a block action:
    {{
      "action": "Block",
      "source_ip": "55.44.33.22"
    }}
    
    Example response structure for no action:
    {{
      "action": "None",
      "source_ip": ""
    }}
    
    Do NOT include any surrounding text, markdown formatting (like ```json), or explanation. 
    Output only the raw JSON object.
    """

    # 2. Call Ollama API
    plan_json = {"action": "None", "source_ip": ""}
    
    try:
        print(f"[{datetime.datetime.now().isoformat()}] Sending request to Ollama for analysis of IP: {src_ip}")
        
        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_ctx": 4096
            }
        }

        # Use httpx to make the synchronous call
        response = httpx.post(OLLAMA_URL, json=payload, timeout=60)
        response.raise_for_status()
        
        result = response.json()
        raw_response_text = result.get('response', '').strip()
        
        # 3. Parse LLM Response
        # Attempt to clean up and parse the LLM's raw output
        cleaned_text = raw_response_text.strip().replace("```json", "").replace("```", "")
        
        try:
            plan = json.loads(cleaned_text)
            plan_json.update(plan)
        except json.JSONDecodeError:
            print(f"Error decoding LLM JSON response. Raw text: {raw_response_text}")
            # If JSON parsing fails, we default to "None" action.
            
    except httpx.ConnectError as e:
        print(f"CRITICAL ERROR: Could not connect to Ollama at {OLLAMA_URL}. Ensure Ollama is running.")
        print(e)
    except httpx.HTTPStatusError as e:
        print(f"HTTP Error from Ollama: {e.response.status_code}")
    except Exception as e:
        print(f"An unexpected error occurred during LLM analysis: {e}")


    # 4. Execute Plan (Only if action is "Block")
    if plan_json.get("action", "").lower() == "block" and plan_json.get("source_ip"):
        ip_to_block = plan_json["source_ip"]
        print(f"[{datetime.datetime.now().isoformat()}] EXECUTION: Blocking IP {ip_to_block}")
        
        # Use the explicit path to the PowerShell executor script
        executor_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'executor', 'apply_plan.ps1')
        
        try:
            # We assume the Agent is running as a service or can call a privileged process.
            # Running the PowerShell script via subprocess
            command = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-File", executor_script,
                "-SourceIp", ip_to_block,
                "-Action", "Block"
            ]
            
            # Subprocess execution requires the entire path to be correct.
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            print(f"Execution Successful. Output: {result.stdout.strip()}")

        except subprocess.CalledProcessError as e:
            print(f"EXECUTION FAILURE: PowerShell script failed with error:\n{e.stderr.strip()}")
            print("Ensure the Collector/Agent is run with Administrator privileges.")
        except FileNotFoundError:
            print(f"EXECUTION FAILURE: Executor script not found at {executor_script}")
        except Exception as e:
            print(f"EXECUTION FAILURE: Unexpected error during execution: {e}")

    return plan_json
