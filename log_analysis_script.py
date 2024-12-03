
import re
import csv
from collections import Counter

# Configuration
failed_login_threshold = 10
log_file_path = 'sample_log.txt'  # Replace with your log file path
csv_file_name = 'log_analysis_results.csv'

# Parse log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

# Count requests per IP
def count_requests_per_ip(log_lines):
    ip_addresses = [line.split()[0] for line in log_lines]
    return Counter(ip_addresses)

# Identify the most accessed endpoint
def most_accessed_endpoint(log_lines):
    endpoints = [re.search(r'"[A-Z]+ (/.*?) HTTP', line).group(1) for line in log_lines if 'HTTP' in line]
    return Counter(endpoints).most_common(1)[0]

# Detect suspicious activity
def detect_suspicious_activity(log_lines, threshold):
    failed_logins = [line.split()[0] for line in log_lines if '401' in line or 'Invalid credentials' in line]
    failed_counts = Counter(failed_logins)
    return {ip: count for ip, count in failed_counts.items() if count > threshold}

# Write results to CSV
def write_to_csv(requests, most_accessed, suspicious, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in requests.items():
            writer.writerow([ip, count])
        writer.writerow([])  # Empty row for separation

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])  # Empty row for separation

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious.items():
            writer.writerow([ip, count])

# Main function
if __name__ == '__main__':
    log_lines = parse_log_file(log_file_path)

    # Process log data
    requests_per_ip = count_requests_per_ip(log_lines)
    most_accessed = most_accessed_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines, failed_login_threshold)

    # Output results
    print("Requests per IP:")
    for ip, count in requests_per_ip.most_common():
        print(f"{ip}: {count}")

    print("\nMost Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip}: {count}")
    else:
        print("No suspicious activity detected.")

    # Save to CSV
    write_to_csv(requests_per_ip, most_accessed, suspicious_activity, csv_file_name)
    print(f"Results saved to {csv_file_name}")
