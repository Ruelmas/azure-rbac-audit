
import csv
import json
from faker import Faker
import random
from datetime import datetime, timedelta

fake = Faker()

# Constants
NUM_USERS = 150
ROLES = ["Reader", "Contributor", "Owner", "User Access Administrator"]
ACTIONS_BY_ROLE = {
    "Reader": ["read", "write", "delete"],  # Allow elevated actions for testing
    "Contributor": ["read", "write", "update", "delete"],
    "Owner": ["read", "write", "update", "delete"],
    "User Access Administrator": ["read", "assignRole"]
}
AGENTS = ["Azure Portal", "CLI", "PowerShell", "SDK"]
# Internal company IP ranges (company network)
INTERNAL_IPS = ["192.168.1.", "10.0.0.", "172.16.0."]
# External suspicious IPs
EXTERNAL_IPS = ["203.0.113.10", "198.51.100.25"]

# --- Generate Role Assignments (CSV) ---
assignments_filename = "azure_role_assignments.csv"
activity_filename = "azure_activity_logs.json"

role_assignments = []
user_data = {}

# Generate role assignments
with open(assignments_filename, mode='w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=["User", "Role", "Scope", "Assignment Date", "PrincipalType", "PrincipalId"])
    writer.writeheader()

    for _ in range(NUM_USERS):
        user_email = fake.email()
        role = random.choice(ROLES)
        user_data[user_email] = {
            "role": role,
            "user_id": fake.uuid4()  # We'll need this for linking activity logs
        }
        writer.writerow({
            "User": user_email,
            "Role": role,
            "Scope": f"/subscriptions/{fake.uuid4()}/resourceGroups/{fake.word()}",
            "Assignment Date": (datetime.utcnow() - timedelta(days=random.randint(10, 180))).isoformat(),
            "PrincipalType": "User",
            "PrincipalId": user_data[user_email]["user_id"]
        })

# --- Generate Activity Logs (JSON) ---
activity_logs = []

# Generate activity logs for each user
for user_email, data in user_data.items():
    # 25% chance for users to have no actions (Remove)
    if random.random() < 0.25:
        num_actions = 0
    else:
        num_actions = random.randint(1, 20)
    
    # Forcing contributors to only do "read" actions (Reduce to Reader)
    if data["role"] == "Contributor" and random.random() < 0.5:  # 50% chance for Contributor to only read
        action = "read"  # Only read actions for contributors to trigger "Reduce to Reader"
    else:
        action = random.choice(ACTIONS_BY_ROLE[data["role"]])

    base_time = datetime.utcnow() - timedelta(days=random.randint(0, 90))

    for _ in range(num_actions):
        # Randomly choose between internal and external IPs
        if random.random() < 0.1:  # 10% chance for external IPs
            ip = random.choice(EXTERNAL_IPS)
        else:
            ip = f"{random.choice(INTERNAL_IPS)}{random.randint(1, 254)}"

        time = base_time + timedelta(minutes=random.randint(1, 10000))
        activity_logs.append({
            "caller": user_email,
            "operationName": {"value": f"Microsoft.Resources/subscriptions/resourceGroups/{action}"},
            "eventTimestamp": time.isoformat(),
            "resourceGroupName": fake.word(),
            "resourceId": f"/subscriptions/{fake.uuid4()}/resourceGroups/{fake.word()}/providers/Microsoft.Compute/virtualMachines/{fake.word()}",
            "ipAddress": ip,
            "agent": random.choice(AGENTS)
        })

# Save activity logs to JSON file
with open(activity_filename, "w") as file:
    json.dump(activity_logs, file, indent=2)

print(f"Generated files: {assignments_filename} and {activity_filename}")
