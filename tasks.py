import logging
import os
import json
from celery_app import celery
from app.models import ScanRequest, ScanResponse, ToolOutput
from app.tool_runner import ToolRunner
from app.utils import reverse_dns_lookup, resolve_to_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def execute_scan_logic(scan_request_data: dict):
    """
    Core scan logic, callable from anywhere.
    """
    try:
        scan_request = ScanRequest(**scan_request_data)
        logger.info(f"Recon worker starting scan for target: {scan_request.target}, ID: {scan_request.scan_id}")

        results = []
        target_domain = None

        if scan_request.target.replace('.', '').isdigit():
            target_domain = reverse_dns_lookup(scan_request.target)
            if target_domain:
                logger.info(f"Resolved IP {scan_request.target} to domain {target_domain}")

        for tool_request in scan_request.tools:
            try:
                current_target = scan_request.target
                if tool_request.name.lower() == 'masscan':
                    current_target = resolve_to_ip(scan_request.target)
                    logger.info(f"Resolved {scan_request.target} to {current_target} for masscan")

                builder = ToolRunner.get_command_builder(tool_request.name.lower())
                command = builder(
                    target=current_target,
                    parameters=tool_request.parameters,
                    scan_id=scan_request.scan_id,
                    tool_name=tool_request.name
                )

                tool_result = ToolRunner.execute_command(
                    command,
                    scan_id=scan_request.scan_id,
                    tool_name=tool_request.name
                )
                results.append(tool_result)
            except Exception as e:
                logger.exception(f"Tool {tool_request.name} failed: {e}")
                results.append(ToolOutput(
                    tool_name=tool_request.name,
                    command=[],
                    return_code=-1,
                    stdout="",
                    stderr=str(e),
                    output_file_paths=[],
                    success=False
                ))

        all_success = all(r.success for r in results)
        any_success = any(r.success for r in results)
        if all_success:
            status = "success"
            message = "All tools executed successfully."
        elif any_success:
            status = "partial_failure"
            message = "Some tools failed."
        else:
            status = "failed"
            message = "All tools failed."

        response = ScanResponse(
            scan_id=scan_request.scan_id,
            target=scan_request.target,
            target_domain=target_domain,
            results=results,
            message=message,
            status=status
        )

        output_dir = os.path.join("/app", "outputs", scan_request.scan_id)
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "final_results.json"), "w", encoding="utf-8") as f:
            f.write(response.model_dump_json(indent=4))

        logger.info(f"Recon scan {scan_request.scan_id} completed.")
        return {"status": "complete", "scan_id": scan_request.scan_id}

    except Exception as e:
        logger.exception("Critical error in Recon worker task")
        # We must raise an exception to make the Argo workflow fail
        raise e

@celery.task(name='tasks.run_recon_scan')
def run_recon_scan(scan_request_data: dict):
    """
    Celery task wrapper.
    """
    return execute_scan_logic(scan_request_data)

