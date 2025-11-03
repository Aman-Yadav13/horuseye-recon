import os
import json
import logging
import sys
import time
import random
import requests
import datetime 
from functools import partial 

from tasks import execute_scan_logic

from google.cloud import pubsub_v1
from google.cloud import storage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ArgoWorker")

FASTAPI_INTERNAL_URL = "http://fastapi-gateway-svc.default.svc.cluster.local:80/api/v1/internal"

def update_scan_status(scan_id: str, status: str):
    """Calls the internal FastAPI endpoint to update the overall Scan status."""
    try:
        payload = {"scan_id": scan_id, "status": status}
        response = requests.post(f"{FASTAPI_INTERNAL_URL}/scan/status", json=payload, timeout=5)
        response.raise_for_status() # Raise an exception for bad status codes
        logger.info(f"Successfully updated Scan {scan_id} status to {status}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to update Scan status to {status} for {scan_id}: {e}")
        # Non-fatal, log the error but allow the workflow to continue

def update_tool_status(scan_id: str, tool_name: str, status: str):
    """Calls the internal FastAPI endpoint to update a specific ToolExecution status."""
    try:
        payload = {
            "scan_id": scan_id,
            "tool_name": tool_name,
            "status": status,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        response = requests.post(f"{FASTAPI_INTERNAL_URL}/tool/status", json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Successfully updated Tool {tool_name} for Scan {scan_id} to {status}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to update Tool {tool_name} status to {status} for {scan_id}: {e}")
        # Non-fatal, log the error but allow the tool to run

def upload_to_gcs(bucket_name: str, scan_id: str, payload_json: str):
    """
    Uploads the vulnerability payload string to GCS.
    File will be at gs://[bucket_name]/[scan_id]/vulnr-payload.json
    """
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        blob_path = f"data/{scan_id}/vulnr-payload.json"
        blob = bucket.blob(blob_path)
        
        blob.upload_from_string(payload_json, content_type="application/json")
        
        logger.info(f"Successfully uploaded vulnr payload to gs://{bucket_name}/{blob_path}")

    except Exception as e:
        logger.exception(f"CRITICAL: Failed to upload payload to GCS: {e}")
        # Unlike Pub/Sub, this is a critical failure.
        # If this fails, the vuln scan cannot run.
        sys.exit(1)

def publish_to_pubsub(project_id: str, topic_id: str, scan_id: str, target: str, max_retries: int = 5):
    """
    Publishes a message to a Pub/Sub topic with production-grade retries.
    """
    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project_id, topic_id)
    
    message_data = {
        "scan_id": scan_id,
        "target": target,
        "status": "recon_complete"
    }
    data = json.dumps(message_data).encode("utf-8")

    base_delay_seconds = 1
    jitter_max = 0.5

    for attempt in range(max_retries):
        try:
            future = publisher.publish(topic_path, data)
            message_id = future.result(timeout=30)
            logger.info(f"Successfully published message {message_id} to {topic_path} on attempt {attempt + 1}")
            return
            
        except Exception as e:
            logger.warning(f"Failed to publish Pub/Sub message (Attempt {attempt + 1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                logger.error(f"CRITICAL: Failed to publish Pub/Sub message after {max_retries} attempts. Giving up.")
                return 

            delay = (base_delay_seconds * 2**attempt) + (random.random() * jitter_max)
            logger.info(f"Retrying in {delay:.2f} seconds...")
            time.sleep(delay)


def main():
    logger.info("--- Argo Worker Entrypoint ---")

    try:
        scan_id = os.environ['SCAN_ID']
        target = os.environ['TARGET']
        recon_tools_payload_json = os.environ['RECON_TOOLS_PAYLOAD_JSON'] # Renamed for clarity
        vulnr_tools_payload_json = os.environ['VULNR_TOOLS_PAYLOAD_JSON']

        gcp_project_id = os.environ['GCP_PROJECT_ID']
        pubsub_topic_id = os.environ['PUB_SUB_TOPIC']
        gcs_bucket_name = os.environ['GCS_BUCKET_NAME']

    except KeyError as e:
        logger.error(f"Missing environment variable: {e}")
        sys.exit(1)

    logger.info(f"Starting scan for ID: {scan_id} on Target: {target}")

    try:
        tools_list = json.loads(recon_tools_payload_json)
        scan_request_data = {
            "scan_id": scan_id,
            "target": target,
            "tools": tools_list
        }
        logger.info(f"Successfully parsed {len(tools_list)} recon tools.")
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse RECON_TOOLS_PAYLOAD_JSON: {e}")
        sys.exit(1)

    try:
        update_scan_status(scan_id, "recon_running")

        tool_status_callback = partial(update_tool_status, scan_id)

        logger.info("Handing off to recon scan logic...")
        # --- NEW: Pass the callback to the logic function ---
        result = execute_scan_logic(scan_request_data, tool_status_callback)
        logger.info(f"Recon scan logic completed. Result: {result}")

        logger.info("Uploading vulnerability payload to GCS for next step...")
        upload_to_gcs(gcs_bucket_name, scan_id, vulnr_tools_payload_json)

        # --- NEW: Update Scan status to 'recon_complete' ---
        update_scan_status(scan_id, "recon_complete")

        logger.info("Recon complete. Publishing to Pub/Sub...")
        publish_to_pubsub(gcp_project_id, pubsub_topic_id, scan_id, target)
        
        logger.info("--- Argo Worker Complete ---")
        sys.exit(0)

    except Exception as e:
        logger.exception(f"Scan logic failed with a critical error: {e}")
        update_scan_status(scan_id, "failed")
        logger.info("--- Argo Worker Failed ---")
        sys.exit(1)

if __name__ == "__main__":
    main()

