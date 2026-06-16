from veracode_api_py import Applications, Sandboxes, XMLAPI
from veracode_api_py.sca import ComponentActivity
import xml.etree.ElementTree as ET
import pick
import csv
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 5

def xml_to_json(element):
    data = {}
    if element.attrib:
        data.update(element.attrib)

    children = list(element)
    if children:
        for child in children:
            child_value = xml_to_json(child)
            if child.tag in data:
                if isinstance(data[child.tag], list):
                    data[child.tag].append(child_value)
                else:
                    data[child.tag] = [data[child.tag], child_value]
            else:
                data[child.tag] = child_value

    text = element.text.strip() if element.text and element.text.strip() else None
    if text:
        if data:
            data["text"] = text
        else:
            return text

    return data

def parse_xml(xml_data):
    if not xml_data:
        return None
    try:
        root = ET.fromstring(xml_data)

        return [xml_to_json(child) for child in root]
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML data - {e}")
        return None

def get_user_input():
    application_id = None
    selected_application = None
    while application_id is None:
        application_name = input("Enter the application you want to fetch (empty to quit): ").strip()
        if not application_name:
            break
        # Get the application GUID
        candidates = Applications().get_by_name(application_name)
        if candidates:
            for application in candidates:
                if application['profile']["name"].lower() == application_name.lower():
                    selected_application = application
                    application_id = selected_application['id']
                    print(f"Found application: {selected_application['profile']['name']} (ID: {application_id})")
                    break
            if application_id:
                break

            print(f"Found {len(candidates)} potential applications:")
            option, index = pick.pick([application['profile']["name"] for application in candidates], "Select Application to Fetch", indicator='=>', default_index=0)
            selected_application = candidates[index]
            application_id = selected_application['id']
            print(f"Selected application: {option} (ID: {application_id})")
        else:
            print(f"No application found with name '{application_name}'.")

    selected_sandbox = None
    sandboxes = Sandboxes().get_all(selected_application["guid"])
    if sandboxes:
        option, index = pick.pick(["Yes", "No"], "Do you want to download sandbox data?", indicator='=>', default_index=0)
        if index == 0:
            option, index = pick.pick([sandbox["name"] for sandbox in sandboxes], "Select Sandbox to Fetch", indicator='=>', default_index=0)
            selected_sandbox = sandboxes[index]
            print(f"Selected sandbox: {option} (ID: {selected_sandbox['id']})")
    
    file_name = None
    while file_name is None:
        file_name = input("Enter the file name to save the results (default: sca_results.csv): ").strip()
        if file_name:
            if not "." in file_name:
                file_name = file_name + ".csv"
            elif not file_name.lower().endswith('.csv'):
                file_name = None
            print(f"File name {file_name} is invalid. File extension must be .csv")

    return application_id, selected_sandbox["id"] if selected_sandbox else None, file_name

def try_get_all_scans(app_id, attempt=1):
    logger.info(f"Fetching scan list for app {app_id}")
    try:
        raw = XMLAPI().get_build_list(app_id)
        return parse_xml(raw)
    except Exception as e:
        logger.warning(f"Attempt {attempt}: Failed to get scans for app {app_id} - {e}")
        if attempt < MAX_ATTEMPTS:
            time.sleep(2 ** attempt)
            return try_get_all_scans(app_id, attempt + 1)
        else:
            logger.error(f"Exceeded maximum retry attempts for app {app_id}. Skipping.")
            return []
        
def try_get_all_sandbox_scans(app_id, sandbox_id, attempt=1):
    logger.info(f"Fetching sandbox scan list for app {app_id} sandbox {sandbox_id}")
    try:
        raw = XMLAPI().get_build_list(app_id, sandbox_id)
        return parse_xml(raw)
    except Exception as e:
        logger.warning(f"Attempt {attempt}: Failed to get sandbox scans for app {app_id} - {e}")
        if attempt < MAX_ATTEMPTS:
            time.sleep(2 ** attempt)
            return try_get_all_sandbox_scans(app_id, sandbox_id, attempt + 1)
        else:
            logger.error(f"Exceeded maximum retry attempts for app {app_id}. Skipping.")
            return []
        
def try_get_next_safe_version(library_id, attempt=1):
    logger.info(f"Fetching next safe version for {library_id}")
    try:
        return ComponentActivity().get(library_id)
    except Exception as e:
        logger.warning(f"Attempt {attempt}: Failed to fetch next safe version for {library_id} - {e}")
        if attempt < MAX_ATTEMPTS:
            time.sleep(2 ** attempt)
            return try_get_next_safe_version(library_id, attempt+1)
        else:
            logger.error(f"Exceeded maximum retry attempts for library {library_id}. Skipping.")
            return {}

def parse_safe_versions(safe_version_list):
    if not safe_version_list:
        return "No safe version available"
    return str(", ".join(safe_version_list))
    

def parse_finding(finding):
    return {
        "library_id": finding.get("library_id", "N/A"),
        "library_name": finding.get("library", "N/A"),
        "version": finding.get("version", "N/A"),
        "total_vulnerabilities": finding.get("vulnerabilities", "N/A"),
        "highest_severity": finding.get("max_cvss_score", "N/A"),
        "safe_versions": parse_safe_versions(try_get_next_safe_version(finding.get("library_id", "")).get("safe_versions", [])),
    }

def get_latest_scan_id(application_id, sandbox_id):
    scans = try_get_all_scans(application_id) if not sandbox_id else try_get_all_sandbox_scans(application_id, sandbox_id)
    return scans[-1]["build_id"] if scans else None

def main():
    application_id, sandbox_id, file_name = get_user_input()
    scan_id = get_latest_scan_id(application_id, sandbox_id)

    detailed_report = parse_xml(XMLAPI().get_detailed_report(scan_id))

    if not detailed_report:
        logger.error("Unable to download scan report for:")
        logger.error(f" - Application '{application_id}'")
        if sandbox_id:
            logger.error(f" - Sandbox ID '{sandbox_id}'")
        if scan_id:
            logger.error(f" - Scan ID '{scan_id}'")
        return
    
    sca_findings = next(iter([element for element in detailed_report if "third_party_components" in element]), {}).get(
        "{https://www.veracode.com/schema/reports/export/1.0}vulnerable_components", {}).get(
        "{https://www.veracode.com/schema/reports/export/1.0}component", [])
    vulnerabilities = []
    for finding in sca_findings:
        if finding['{https://www.veracode.com/schema/reports/export/1.0}vulnerabilities']:
            vulnerabilities.append(parse_finding(finding))

    if vulnerabilities:
        with open(file_name, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['library_id', 'library_name', 'version', 'total_vulnerabilities', 'highest_severity', 'safe_versions']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for vulnerability in vulnerabilities:
                writer.writerow(vulnerability)


if __name__ == "__main__":
    main()