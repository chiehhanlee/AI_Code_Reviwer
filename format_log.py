#!/usr/bin/env python3
import json
import sys
import os

def main():
    input_file = "ai_request_log.jsonl"
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        sys.exit(1)

    output_file = os.path.splitext(input_file)[0] + ".md"
    
    print(f"Reading from {input_file}...")
    
    with open(input_file, 'r', encoding='utf-8') as f_in, \
         open(output_file, 'w', encoding='utf-8') as f_out:
         
        f_out.write("# AI Security Review Prompts Log\n\n")
        
        count = 0
        for i, line in enumerate(f_in, 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                data = json.loads(line)
                func_name = data.get("func_name")
                prompt = data.get("prompt", "")
                timestamp = data.get("timestamp", "")

                display_name = func_name if func_name else "Global / Full File Context"

                count += 1
                f_out.write(f"## {count}. Target: `{display_name}`\n\n")
                if timestamp:
                    f_out.write(f"**Timestamp:** {timestamp}\n\n")
                f_out.write(f"{prompt.strip()}\n\n")
                f_out.write("---\n\n")
            except json.JSONDecodeError:
                print(f"Warning: Could not parse JSON on line {i}")

    print(f"Successfully formatted {count} requests to {output_file}")

if __name__ == "__main__":
    main()
