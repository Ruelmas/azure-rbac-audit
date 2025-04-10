import csv
import json
from datetime import datetime
from collections import defaultdict
from dateutil.parser import parse as parse_date

# Input and output file paths (relative to the script's current working directory)
assignments_file = "azure_role_assignments.csv"
logs_file = "azure_activity_logs.json"
output_file = "role_usage_audit.json"

# --- Load role assignments ---
role_assignments = {}
with open(assignments_file) as f:
    reader = csv.DictReader(f)
    for row in reader:
        user = row.get("User", "").strip().lower()
        role_assignments[user] = {
            "Role": row.get("Role", ""),
            "Scope": row.get("Scope", ""),
            "Assignment Date": row.get("Assignment Date", ""),
            "PrincipalType": row.get("PrincipalType", ""),
            "PrincipalId": row.get("PrincipalId", "")
        }

# --- Load activity logs ---
with open(logs_file) as f:
    logs = json.load(f)

user_activity = defaultdict(list)
for entry in logs:
    user = entry.get("caller", "").strip().lower()
    op = entry.get("operationName", {})
    action = op.get("value") if isinstance(op, dict) else op
    timestamp = entry.get("eventTimestamp", "")
    if user and action and timestamp:
        user_activity[user].append({
            "action": action.split("/")[-1].lower(),
            "timestamp": timestamp,
            "ip": entry.get("ipAddress", "unknown"),
            "agent": entry.get("agent", "unknown"),
            "resource": entry.get("resourceId", "")
        })

# --- Generate audit report ---
audit_data = []
now = datetime.utcnow()

for user, role_data in role_assignments.items():
    actions = user_activity.get(user, [])
    action_names = [a["action"] for a in actions]
    unique_actions = sorted(set(action_names))
    count = len(actions)

    if count:
        timestamps = [parse_date(a["timestamp"]) for a in actions]
        first = min(timestamps)
        last = max(timestamps)
        inactive_days = (now - last).days
        agent = actions[-1]["agent"]
        ip = actions[-1]["ip"]
    else:
        first = last = None
        inactive_days = None
        agent = ip = None

    # Suggestion logic
    if count == 0:
        suggestion = "Remove - No activity"
    elif role_data["Role"] == "Reader" and any(a != "read" for a in unique_actions):
        suggestion = "Misuse - Reader doing elevated actions"
    elif role_data["Role"] == "Contributor" and set(unique_actions) <= {"read"}:
        suggestion = "Reduce to Reader - Read-only usage"
    elif inactive_days and inactive_days > 90:
        suggestion = "Reduce - Inactive > 90 days"
    else:
        suggestion = "Keep - Active usage"

    audit_data.append({
        "User": user,
        "Role": role_data["Role"],
        "Scope": role_data["Scope"],
        "Assignment Date": role_data["Assignment Date"],
        "Actions": ",".join(unique_actions),
        "Action Count": count,
        "First Activity": first.isoformat() if first else None,
        "Last Activity": last.isoformat() if last else None,
        "Inactive Days": inactive_days,
        "Agent": agent,
        "IP": ip,
        "Flags": [],
        "Suggestion": suggestion
    })

# Save to output file
with open(output_file, "w") as f:
    json.dump(audit_data, f, indent=2)
print(f"AUDIT COMPLETE → {output_file}")
