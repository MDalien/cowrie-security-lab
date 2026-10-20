
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_FILE = Path.home() / "cowrie/var/log/cowrie/cowrie.json"

events = []
event_counts = Counter()
source_ips = Counter()
usernames = Counter()
commands = Counter()
sessions = {}

def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

with LOG_FILE.open() as log_file:
    for line in log_file:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        events.append(event)
        event_id = event.get("eventid", "unknown")
        event_counts[event_id] += 1

        if event.get("src_ip"):
            source_ips[event["src_ip"]] += 1

        if event.get("username"):
            usernames[event["username"]] += 1

        if event_id == "cowrie.command.input":
            command = event.get("input", "").strip()
            if command:
                commands[command] += 1

        session_id = event.get("session")
        timestamp = parse_time(event.get("timestamp"))

        if session_id and timestamp:
            record = sessions.setdefault(
                session_id, {"start": timestamp, "end": timestamp}
            )
            record["start"] = min(record["start"], timestamp)
            record["end"] = max(record["end"], timestamp)

auth_success = event_counts["cowrie.login.success"]
auth_failed = event_counts["cowrie.login.failed"]
failed_commands = event_counts["cowrie.command.failed"]
total_sessions = event_counts["cowrie.session.connect"]

print("\n=== Cowrie Security Investigation Report ===")
print(f"Total events processed: {len(events)}")
print(f"SSH sessions started:  {total_sessions}")
print(f"Login successes:       {auth_success}")
print(f"Login failures:        {auth_failed}")
print(f"Failed commands:       {failed_commands}")
print(f"Unique source IPs:     {len(source_ips)}")

print("\n=== Source IPs ===")
for ip, count in source_ips.most_common():
    print(f"{ip}: {count} events")

print("\n=== Usernames Observed ===")
for username, count in usernames.most_common():
    print(f"{username}: {count} events")

print("\n=== Most Common Commands ===")
for command, count in commands.most_common(10):
    print(f"{command}: {count}")

print("\n=== Session Durations ===")
for session_id, record in sessions.items():
    duration = (record["end"] - record["start"]).total_seconds()
    print(f"{session_id}: {duration:.1f} seconds")

print("\n=== Event Types ===")
for event_id, count in event_counts.most_common():
    print(f"{event_id}: {count}")
