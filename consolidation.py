import pandas as pd
import os
import argparse
import re


# Parse command-line arguments
def parse_args():
    #parser = argparse.ArgumentParser(description='Code executes based on 2 different arguments.\n1.Consolidate used with a folder of csv reports will generate 1 consolidated file. \n2.Summary run with 1 file will generate the findings summary for all individual IPs')
    parser = argparse.ArgumentParser(
        description='Code executes based on 2 different arguments.\n'
                '1. Consolidate: run with a folder of CSV reports to generate 1 consolidated file.\n'
                '2. Summary: run with 1 csv file to generate the findings summary for all individual IPs',
                formatter_class=argparse.RawTextHelpFormatter
            )

    parser.add_argument('operation', choices=['consolidate', 'summary'], help='Operation to perform: "consolidate" or "summary"')
    parser.add_argument('input_path', help='Path to the folder containing CSV files (for consolidate) or path to a single CSV file (for summary)')
    parser.add_argument('--format-cve', action='store_true', help='Format Affected Host as "<IPs> <top 3 CVEs of latest year>"')
    return parser.parse_args()

# for generating individual csv files for findings and remediation.
def summary_process(csv_file_path):
    # Read the single consolidated CSV file into a DataFrame
    df = pd.read_csv(csv_file_path)
    
    # Get the directory where the input file is located
    csv_directory = os.path.dirname(csv_file_path)
    
    # Extract unique IP addresses from the 'Affected Host' column
    # The format is "IP/CVE" so we need to extract just the IP part
    all_ips = set()
    for hosts in df['Affected Host'].dropna():
        # Split by spaces and extract IP from each "IP/CVE" entry
        host_entries = hosts.split('  ')
        for entry in host_entries:
            if '/' in entry:
                ip = entry.split('/')[0]
                all_ips.add(ip)
    
    # Convert to sorted list for consistent ordering
    all_ips = sorted(list(all_ips))
    
    # Create a summary DataFrame
    summary_data = []
    
    for ip in all_ips:
        # Count vulnerabilities for this IP by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # Check each row to see if this IP is affected
        for idx, row in df.iterrows():
            hosts = row['Affected Host']
            severity = row['Severity']
            
            if pd.notna(hosts) and ip in hosts:
                # Count by severity
                if severity == 'Critical':
                    critical_count += 1
                elif severity == 'High':
                    high_count += 1
                elif severity == 'Medium':
                    medium_count += 1
                elif severity == 'Low':
                    low_count += 1
        
        # Add this IP's summary to the list
        summary_data.append({
            'IP Address': ip,
            'Critical': critical_count,
            'High': high_count,
            'Medium': medium_count,
            'Low': low_count
        })
    
    # Create the summary DataFrame
    summary_df = pd.DataFrame(summary_data)
    
    # Save the summary table
    # Ensure .csv extension for consistent downloads
    summary_file_path = os.path.join(csv_directory, "vulnerability_summary.csv")
    summary_df.to_csv(summary_file_path, index=False)
    print(f"Vulnerability summary by IP saved as {summary_file_path}")

# consolidate all files
def _format_cve_string(data: str) -> str:
    # Tokenize by any whitespace; handle entries like "ip/CVE-YYYY-NNNN"
    tokens = data.split()
    ip_set = set()
    cve_by_year = {}
    has_cve_pair = False

    for token in tokens:
        if '/' in token:
            ip_part, cve_part = token.split('/', 1)
            ip = ip_part.strip()
            cve = cve_part.strip()

            if ip:
                ip_set.add(ip)

            match = re.match(r'^CVE-(\d{4})-(\d+)$', cve)
            if match:
                has_cve_pair = True
                year = int(match.group(1))
                num = int(match.group(2))
                cve_by_year.setdefault(year, set()).add((num, cve))
        else:
            # Bare IP token; keep only if we are otherwise formatting due to CVE presence
            ip_candidate = token.strip()
            if ip_candidate:
                ip_set.add(ip_candidate)

    # If there are no valid CVE pairs present, return the original string unchanged
    if not has_cve_pair:
        return data

    # Determine latest year with CVEs
    selected_cves = []
    if cve_by_year:
        latest_year = max(cve_by_year.keys())
        # Get top 3 by number within latest year
        year_entries = sorted(cve_by_year[latest_year], key=lambda x: x[0], reverse=True)
        selected_cves = [cve for _, cve in year_entries[:3]]

    parts = []
    if ip_set:
        parts.append(' '.join(sorted(ip_set)))
    if selected_cves:
        parts.append(' '.join(selected_cves))
    return ' '.join(parts)


def format_cve_file(input_csv_path: str, output_csv_path: str | None = None) -> str:
    """Format each Affected Host cell in a pre-consolidated CSV and write output.
    Expects columns including 'Affected Host'. Returns the output path.
    """
    df = pd.read_csv(input_csv_path)
    if 'Affected Host' not in df.columns:
        raise ValueError("Input CSV must contain 'Affected Host' column")
    df['Affected Host'] = df['Affected Host'].astype(str).apply(_format_cve_string)
    if output_csv_path is None:
        base_dir = os.path.dirname(input_csv_path)
        output_csv_path = os.path.join(base_dir, 'formatted_cve.csv')
    df.to_csv(output_csv_path, index=False)
    return output_csv_path


def consolidated_process(csv_directory, format_cve: bool = False):
        
    # Check if the provided directory exists
    if not os.path.isdir(csv_directory):
        print(f"Error: The directory '{csv_directory}' does not exist.")
        return

    # List all CSV files in the folder
    csv_files = [f for f in os.listdir(csv_directory) if f.endswith('.csv')]

    if not csv_files:
        print(f"No CSV files found in the directory: {csv_directory}")
        return

    df_list = []

    # Read each CSV file and append to the list
    for file in csv_files:
        file_path = os.path.join(csv_directory, file)
        df = pd.read_csv(file_path)
        # Remove rows where 'Severity' (Risk) is blank or NaN
        df = df[df['Risk'].notna()]
        df_list.append(df)

    # Combine all CSV files into a single DataFrame
    combined_df = pd.concat(df_list, ignore_index=True)

    # Data Transformation: Rename and reformat the columns
    transformed_df = pd.DataFrame()

    # Apply the column transformations
    transformed_df['Name of the Vulnerability'] = combined_df['Name']
    transformed_df['Severity'] = combined_df['Risk']
    transformed_df['Port_Protocol'] = combined_df['Port'].astype(str) + '/' + combined_df['Protocol']
    transformed_df['Vulnerability Description'] = combined_df['Description']

    transformed_df['Affected Host'] = combined_df['Host'].astype(str)
    transformed_df['Affected Host'] = transformed_df['Affected Host'] + '/' + combined_df['CVE'].fillna('')
    transformed_df['Affected Host'] = transformed_df['Affected Host'].str.replace('/$', '', regex=True)

    # If requested, format each Affected Host cell individually
    if format_cve:
        transformed_df['Affected Host'] = transformed_df['Affected Host'].apply(_format_cve_string)

    transformed_df['Solution'] = combined_df['Solution']


      # Grouping and aggregation (join unique, per-row already formatted if enabled)
    grouped_df = transformed_df.groupby(
        ['Name of the Vulnerability', 'Severity', 'Port_Protocol', 'Vulnerability Description', 'Solution'], as_index=False
    ).agg({
        'Affected Host': lambda x: '  '.join(x.unique())
    })

    # Save the result to a CSV file
    grouped_df.to_csv('consolidated_vulnerability_report.csv', index=False)

    print("Data was combined and saved successfully as 'consolidated_vulnerability_report.csv'")


def main():
    args = parse_args()

    if args.operation == 'consolidate':
        consolidated_process(args.input_path, format_cve=args.format_cve)
    elif args.operation == 'summary':
        # Check if the input path is a file
        if not os.path.isfile(args.input_path):
            print(f"Error: The file '{args.input_path}' does not exist.")
            return
        summary_process(args.input_path)

if __name__ == "__main__":
    main()

