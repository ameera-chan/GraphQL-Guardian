import json
import sys
import os

def verify_coverage(report_path):
    if not os.path.exists(report_path):
        print(f"[-] Report not found at {report_path}")
        sys.exit(1)
        
    with open(report_path, 'r') as f:
        data = json.load(f)
        
    if isinstance(data, dict) and 'findings' in data:
        findings = data['findings']
    else:
        findings = data
        
    print(f"[*] Loaded {len(findings)} findings from report.")
    
    # Define expected findings (Title or Category + partial description)
    expected_issues = [
        {"category": "CONFIG", "title": "Introspection"},
        {"category": "CONFIG", "title": "Public GraphiQL"},
        {"category": "DOS", "title": "Alias Overloading"},
        {"category": "DOS", "title": "Batch Queries"},
        {"category": "INJECTION", "location": "createPaste"},
        {"category": "INJECTION", "location": "importPaste"},
    ]
    
    found_count = 0
    missing = []
    
    for expected in expected_issues:
        found = False
        for finding in findings:
            # Check category
            if finding.get('category') != expected['category']:
                continue
                
            # Check title if specified
            if 'title' in expected and expected['title'] not in finding.get('title', ''):
                continue
                
            # Check location if specified
            if 'location' in expected:
                # location field in finding might be mapped to operation_name or field
                # In JSON report, we have 'endpoint', 'operation_name', 'field'
                # But let's check if any field contains the string
                loc_match = False
                if expected['location'] in str(finding.get('operation_name', '')): loc_match = True
                if expected['location'] in str(finding.get('field', '')): loc_match = True
                if expected['location'] in str(finding.get('description', '')): loc_match = True
                
                if not loc_match:
                    continue
            
            found = True
            break
        
        if found:
            found_count += 1
            print(f"[+] Found expected issue: {expected}")
        else:
            missing.append(expected)
            print(f"[-] Missing expected issue: {expected}")
            
    print(f"\nCoverage: {found_count}/{len(expected_issues)}")
    
    if missing:
        print("[-] Some expected issues were not found.")
        sys.exit(1)
    else:
        print("[+] All expected issues found!")
        sys.exit(0)

if __name__ == "__main__":
    verify_coverage("reports/dvga_full.json")
