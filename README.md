🔐 Azure RBAC Role Usage Audit Tool
A lightweight Azure security tool designed to audit Azure Role-Based Access Control (RBAC) usage across your cloud environment.

Identify potential security risks like drift, misuse, stale roles, and over-privilege—without requiring Microsoft Defender for Cloud, Privileged Identity Management (PIM), or specific E5 licenses.

🧠 What It Does
This tool analyzes Azure role assignments compared against actual user activity logs to answer critical questions:

Unused Roles: Who has assigned roles they have never utilized?
Stale Permissions: Who hasn't used their assigned permissions in over 90 days?
Overprivileged Contributors: Which users with 'Contributor' roles are only performing 'read' actions?
Potential Misuse: Are users with 'Reader' roles performing actions beyond their intended permissions?
Results are presented in a zero-dependency, fully static HTML viewer, making the report easily portable and shareable.

✅ Key Detections
The audit specifically flags scenarios such as:

Situation	Flagged As	Suggested Action
Reader performing "write" or "delete"	Misuse - Reader doing elevated actions	Investigate Activity
Contributor only performing "read"	Potential Overprivilege	Reduce to Reader
Any role with 0 actions recorded	Unused Role Assignment	Remove Role
Any user inactive > 90 days	Stale Role Assignment	Reduce/Remove Role

Export to Sheets
The tool also highlights potentially suspicious IP addresses, user agents, and access patterns found in the activity logs.

🔍 Demo
🎯 Live HTML Viewer Example: RBAC Audit Demo (Hosted)
🧪 Integration Example (Portfolio): See the RBAC section at www.ruelsresume.com
📂 File Structure
File	Description
generate_rbac_mock_data_with_all_states.py	Generates Faker-based mock data (CSV roles, JSON activity) for testing.
Secaudit.py	The core audit script. Compares roles vs. activity and generates JSON output.
RBACaudit.html	Static HTML frontend viewer. Reads the audit JSON data.
role_usage_audit.json	Sample JSON output file containing the audit results.
README.md	This file.

Export to Sheets
⚙️ How To Use It
1. Prepare Your Data (Option A: Mock Data)
Generate sample data for testing purposes:

Bash

python generate_rbac_mock_data_with_all_states.py
This creates:

azure_role_assignments.csv (Simulated users and their assigned RBAC roles)
azure_activity_logs.json (Simulated user activity logs)
1. Prepare Your Data (Option B: Real Azure Data)
Export your actual Azure data into the required formats:

Role Assignments: A .csv file listing user principals and their assigned roles (similar structure to the mock azure_role_assignments.csv).
Activity Logs: Azure Monitor activity logs exported as a .json file (similar structure to the mock azure_activity_logs.json).
(Note: Ensure your export method captures the necessary details like User Principal Name/ID, Role Definition Name/ID, Action, Timestamp, Caller IP Address, etc.)

2. Run the Audit
Execute the audit script, pointing it to your data files (it defaults to the mock filenames):

Bash

python Secaudit.py
This script will:

Parse the role assignments and activity logs.
Analyze usage patterns to detect the scenarios listed above.
Output the findings and suggestions to role_usage_audit.json.
3. Visualize the Results
Option 1 (Local): Open the RBACaudit.html file directly in your web browser. It will look for role_usage_audit.json in the same directory.
Option 2 (Hosted):
Upload the generated role_usage_audit.json to a web-accessible location (like Azure Blob Storage).
Modify the Workspace URL inside RBACaudit.html to point to your hosted JSON file.
Open the modified RBACaudit.html.
The viewer requires no backend infrastructure.

💡 Why I Built This
During my time in IT support roles, it became clear that while Azure roles were assigned, verification of their actual usage was often overlooked. Existing Microsoft tools typically required higher-tier licenses (like Defender for Cloud or PIM) for this type of analysis. Seeing a need for a simpler, license-independent solution, I developed this tool, refined it using real-world scenarios.

🔐 Security Considerations
This tool is designed with security in mind:

No Direct Azure Access: It does not require Azure SDKs, Graph API permissions, or credentials to run the audit itself. It operates on exported data.
Data Handling: The audit script processes data locally. No sensitive information or secrets are transmitted externally by the tool.
Flexible Hosting: You can run the audit and host the static HTML report entirely within your private network, on Azure Blob Storage with restricted access, or embed it within internal dashboards.
