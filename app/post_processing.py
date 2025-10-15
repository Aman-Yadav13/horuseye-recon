import os
import logging
from typing import Dict, Callable, List
from app.gcs_utils import upload_file_to_gcs, delete_local_directory

logger = logging.getLogger(__name__)

_post_processor_registry: Dict[str, Callable] = {}

def register_post_processor(tool_name: str) -> Callable:
    """A decorator to register a post-processing function for a tool."""
    def decorator(func: Callable) -> Callable:
        _post_processor_registry[tool_name.lower()] = func
        logger.info(f"Registered post-processor for tool: {tool_name}")
        return func
    return decorator

def get_post_processor(tool_name: str) -> Callable:
    """Retrieves the post-processing function for a tool, or a default."""
    processor = _post_processor_registry.get(tool_name.lower(), default_post_processor)
    logger.info(f"Using post-processor '{processor.__name__}' for tool '{tool_name}'")
    return processor

def default_post_processor(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Default handler: Uploads all generated files for review and cleans up.
    """
    logger.info(f"Running default post-processor for {tool_name}")
    all_uploads_succeeded = True
    for file_path in output_files:
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
            # Upload all files to the 'review' folder by default
            gcs_path = f"data/{scan_id}/recon/{tool_name}/review/{filename}"
            if not upload_file_to_gcs(file_path, gcs_path):
                all_uploads_succeeded = False
    
    if all_uploads_succeeded:
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to GCS upload failures.")

@register_post_processor("masscan")
def post_process_masscan(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Masscan.
    - Uploads the JSON result file to both LLM and review directories.
    - Deletes all other local files.
    """
    logger.info("Running custom post-processor for Masscan")

    json_file = os.path.join(output_dir, "masscan_scan.json")
    uploads_succeeded = []

    if os.path.exists(json_file):
        llm_success = upload_file_to_gcs(
            json_file, f"data/{scan_id}/recon/{tool_name}/llm/masscan_scan.json"
        )
        uploads_succeeded.append(llm_success)
        
        review_success = upload_file_to_gcs(
            json_file, f"data/{scan_id}/recon/{tool_name}/review/masscan_scan.json"
        )
        uploads_succeeded.append(review_success)
    else:
        logger.error(f"Masscan JSON output not found at {json_file}")
        uploads_succeeded.append(False)

    if all(uploads_succeeded):
        logger.info("Masscan artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Masscan upload failures.")
        
@register_post_processor("amass")
def post_process_amass(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Amass.
    - Uploads the text result file to both LLM and review directories.
    - Deletes all other local files.
    """
    logger.info("Running custom post-processor for Amass")

    txt_file = os.path.join(output_dir, "amass_scan.txt")
    uploads_succeeded = []

    if os.path.exists(txt_file):
        llm_success = upload_file_to_gcs(
            txt_file, f"data/{scan_id}/recon/{tool_name}/llm/amass_scan.txt"
        )
        uploads_succeeded.append(llm_success)
        
        review_success = upload_file_to_gcs(
            txt_file, f"data/{scan_id}/recon/{tool_name}/review/amass_scan.txt"
        )
        uploads_succeeded.append(review_success)
    else:
        logger.error(f"Amass text output not found at {txt_file}")
        uploads_succeeded.append(False)

    if all(uploads_succeeded):
        logger.info("Amass artifacts uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Amass upload failures.")
        
@register_post_processor("subfinder")
def post_process_subfinder(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for Subfinder.
    - Uploads the JSON result file for review only.
    - Does not create an LLM file.
    - Deletes all other local files.
    """
    logger.info("Running custom post-processor for Subfinder")

    json_file = os.path.join(output_dir, "subfinder_scan.json")
    upload_succeeded = False

    if os.path.exists(json_file):
        upload_succeeded = upload_file_to_gcs(
            json_file, f"data/{scan_id}/recon/{tool_name}/review/subfinder_scan.json"
        )
    else:
        logger.error(f"Subfinder JSON output not found at {json_file}")

    if upload_succeeded:
        logger.info("Subfinder artifact uploaded successfully. Cleaning up local directory.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to Subfinder upload failure.")

@register_post_processor("theharvester")
def post_process_theharvester(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for theHarvester.
    - Uploads JSON to LLM and review.
    - Uploads stdout to review only.
    """
    logger.info("Running custom post-processor for theHarvester")
    json_file = os.path.join(output_dir, "theharvester_scan.json")
    stdout_file = os.path.join(output_dir, "output.stdout")
    uploads_succeeded = []

    if os.path.exists(json_file):
        uploads_succeeded.append(upload_file_to_gcs(
            json_file, f"data/{scan_id}/recon/{tool_name}/llm/theharvester_scan.json"
        ))
        uploads_succeeded.append(upload_file_to_gcs(
            json_file, f"data/{scan_id}/recon/{tool_name}/review/theharvester_scan.json"
        ))
    else:
        logger.warning(f"theHarvester JSON not found at {json_file}")

    if os.path.exists(stdout_file):
        uploads_succeeded.append(upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/recon/{tool_name}/review/output.stdout"
        ))
    else:
        logger.warning(f"theHarvester stdout not found at {stdout_file}")

    if all(uploads_succeeded) and uploads_succeeded:
        logger.info("theHarvester artifacts uploaded successfully. Cleaning up.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to theHarvester upload failures.")

@register_post_processor("recon-ng")
def post_process_recon_ng(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for recon-ng.
    - Uploads HTML report and stdout for review/download.
    """
    logger.info("Running custom post-processor for recon-ng")
    report_file = os.path.join(output_dir, "report.html")
    stdout_file = os.path.join(output_dir, "output.stdout")
    uploads_succeeded = []

    if os.path.exists(report_file):
        uploads_succeeded.append(upload_file_to_gcs(
            report_file, f"data/{scan_id}/recon/{tool_name}/review/report.html"
        ))
    if os.path.exists(stdout_file):
        uploads_succeeded.append(upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/recon/{tool_name}/review/output.stdout"
        ))

    if all(uploads_succeeded) and uploads_succeeded:
        logger.info("recon-ng artifacts uploaded successfully. Cleaning up.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to recon-ng upload failures.")

@register_post_processor("gobuster")
def post_process_gobuster(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for gobuster.
    - Uploads text scan file to review.
    - Uploads stdout to both review and LLM.
    """
    logger.info("Running custom post-processor for gobuster")
    scan_file = os.path.join(output_dir, "gobuster_scan.txt")
    stdout_file = os.path.join(output_dir, "output.stdout")
    uploads_succeeded = []

    if os.path.exists(scan_file):
        uploads_succeeded.append(upload_file_to_gcs(
            scan_file, f"data/{scan_id}/recon/{tool_name}/review/gobuster_scan.txt"
        ))
    if os.path.exists(stdout_file):
        uploads_succeeded.append(upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/recon/{tool_name}/review/output.stdout"
        ))
        uploads_succeeded.append(upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/recon/{tool_name}/llm/gobuster_output.txt"
        ))

    if all(uploads_succeeded) and uploads_succeeded:
        logger.info("gobuster artifacts uploaded successfully. Cleaning up.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to gobuster upload failures.")

@register_post_processor("dirsearch")
def post_process_dirsearch(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for dirsearch.
    - Uploads text scan file for review only.
    """
    logger.info("Running custom post-processor for dirsearch")
    scan_file = os.path.join(output_dir, "dirsearch_scan.txt")
    upload_succeeded = False

    if os.path.exists(scan_file):
        upload_succeeded = upload_file_to_gcs(
            scan_file, f"data/{scan_id}/recon/{tool_name}/review/dirsearch_scan.txt"
        )
    
    if upload_succeeded:
        logger.info("dirsearch artifact uploaded successfully. Cleaning up.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to dirsearch upload failure.")

@register_post_processor("whatweb")
def post_process_whatweb(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for whatweb.
    - Uploads text scan file to both LLM and review.
    """
    logger.info("Running custom post-processor for whatweb")
    scan_file = os.path.join(output_dir, "whatweb_scan.txt")
    uploads_succeeded = []

    if os.path.exists(scan_file):
        uploads_succeeded.append(upload_file_to_gcs(
            scan_file, f"data/{scan_id}/recon/{tool_name}/llm/whatweb_scan.txt"
        ))
        uploads_succeeded.append(upload_file_to_gcs(
            scan_file, f"data/{scan_id}/recon/{tool_name}/review/whatweb_scan.txt"
        ))
    else:
        logger.error(f"whatweb scan file not found at {scan_file}")
        uploads_succeeded.append(False)
    
    if all(uploads_succeeded):
        logger.info("whatweb artifacts uploaded successfully. Cleaning up.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to whatweb upload failures.")

@register_post_processor("nmap")
def post_process_nmap(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for nmap.
    - Uploads stdout to LLM and review.
    - Uploads the XML scan file to review only.
    """
    logger.info("Running custom post-processor for nmap")
    stdout_file = os.path.join(output_dir, "output.stdout")
    xml_file = os.path.join(output_dir, "nmap_scan.xml")
    uploads_succeeded = []

    if os.path.exists(stdout_file):
        uploads_succeeded.append(upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/recon/{tool_name}/llm/nmap_output.txt"
        ))
        uploads_succeeded.append(upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/recon/{tool_name}/review/output.stdout"
        ))
    else:
        logger.warning(f"nmap stdout not found at {stdout_file}")

    if os.path.exists(xml_file):
        uploads_succeeded.append(upload_file_to_gcs(
            xml_file, f"data/{scan_id}/recon/{tool_name}/review/nmap_scan.xml"
        ))
    else:
        logger.warning(f"nmap XML file not found at {xml_file}")

    if all(uploads_succeeded) and uploads_succeeded:
        logger.info("nmap artifacts uploaded successfully. Cleaning up.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to nmap upload failures.")

@register_post_processor("dnsenum")
def post_process_dnsenum(scan_id: str, tool_name: str, output_dir: str, output_files: List[str]):
    """
    Custom post-processor for dnsenum.
    - Uploads all output files (stdout, stderr, XML) for review.
    - Does not create an LLM file.
    """
    logger.info("Running custom post-processor for dnsenum")
    stdout_file = os.path.join(output_dir, "output.stdout")
    stderr_file = os.path.join(output_dir, "output.stderr")
    xml_file = os.path.join(output_dir, "dnsenum_scan.xml")
    uploads_succeeded = []

    if os.path.exists(stdout_file):
        uploads_succeeded.append(upload_file_to_gcs(
            stdout_file, f"data/{scan_id}/recon/{tool_name}/review/output.stdout"
        ))
    if os.path.exists(stderr_file):
        uploads_succeeded.append(upload_file_to_gcs(
            stderr_file, f"data/{scan_id}/recon/{tool_name}/review/output.stderr"
        ))
    if os.path.exists(xml_file):
        uploads_succeeded.append(upload_file_to_gcs(
            xml_file, f"data/{scan_id}/recon/{tool_name}/review/dnsenum_scan.xml"
        ))
    
    if all(uploads_succeeded) and uploads_succeeded:
        logger.info("dnsenum artifacts uploaded successfully. Cleaning up.")
        delete_local_directory(output_dir)
    else:
        logger.error(f"Skipping cleanup for {output_dir} due to dnsenum upload failures.")