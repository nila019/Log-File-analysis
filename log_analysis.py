import re
import csv
from collections import Counter

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# File paths
log_file_path = 'sample.log'
output_csv_path = 'log_analysis_results.csv'

# Regular expressions to parse the log file
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>GET|POST|PUT|DELETE) (?P<endpoint>/[^\s]*) HTTP/\d\.\d".* (?P<status>\d{3}) .*'
)
failed_login_message = "Invalid credentials"

ip_counter = Counter()
endpoint_counter = Counter()
failed_login_attempts = Counter()

# Process the log file
with open(log_file_path, 'r') as log_file:
    for line in log_file:
        match = log_pattern.search(line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint")
            status = match.group("status")

            # Count requests per IP and endpoint access
            ip_counter[ip] += 1
            endpoint_counter[endpoint] += 1

            # Check for suspicious activity (failed logins)
            if status == "401" or failed_login_message in line:
                failed_login_attempts[ip] += 1

# Identify the most frequently accessed endpoint
most_accessed_endpoint, most_accessed_count = endpoint_counter.most_common(1)[0]

# Filter IPs with suspicious activity
suspicious_ips = {
    ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD
}

# Save results to CSV
with open(output_csv_path, 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    
    # Write Requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in ip_counter.most_common():
        writer.writerow([ip, count])
    
    # Write Most Accessed Endpoint
    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint, most_accessed_count])
    
    # Write Suspicious Activity
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])

# Display results in the terminal
print("Requests per IP:")
print("IP Address           Request Count")
for ip, count in ip_counter.most_common():
    print(f"{ip:<20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

print("\nSuspicious Activity Detected:")
if suspicious_ips:
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
else:
    print("No suspicious activity detected.")

print(f"\nResults saved to: {output_csv_path}")
