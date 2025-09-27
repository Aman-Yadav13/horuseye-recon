import logging
import os
from flask import Flask, request, jsonify
from app.models import ScanRequest, ScanResponse, ToolOutput
from app.tool_runner import ToolRunner
from app.utils import reverse_dns_lookup, resolve_to_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Ensure outputs directory exists
outputs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
os.makedirs(outputs_dir, exist_ok=True)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/scan', methods=['POST'])
def execute_scan():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        scan_request = ScanRequest(**data)
        logger.info(f"Received scan request for target: {scan_request.target}, ID: {scan_request.scan_id}")

        results = []
        target_domain = None

        # Basic IP validation and reverse DNS
        if scan_request.target.replace('.', '').isdigit():
            target_domain = reverse_dns_lookup(scan_request.target)
            if target_domain:
                logger.info(f"Target IP {scan_request.target} resolved to domain: {target_domain}")

        # Execute each tool
        for tool_request in scan_request.tools:
            try:
                current_target = scan_request.target
                if tool_request.name.lower() == 'masscan':
                    current_target = resolve_to_ip(scan_request.target)
                    logger.info(f"Resolved {scan_request.target} to {current_target} for masscan")

                builder = ToolRunner.get_command_builder(tool_request.name.lower())
            
                # Pass the ToolParameter objects directly (not as dictionaries)
                command = builder(
                    target=current_target,
                    parameters=tool_request.parameters,
                    scan_id=scan_request.scan_id,
                    tool_name=tool_request.name
                )
                logger.info(f"DRY RUN - Generated Command: {command}")

                tool_result = ToolRunner.execute_command(
                    command, 
                    scan_id=scan_request.scan_id, 
                    tool_name=tool_request.name
                )
                results.append(tool_result)

            except ValueError as e:
                error_result = ToolOutput(
                    tool_name=tool_request.name,
                    command=[],
                    return_code=-1,
                    stdout="",
                    stderr=str(e),
                    output_file_paths=[],
                    success=False
                )
                results.append(error_result)
                logger.error(f"Error with tool {tool_request.name}: {e}")
            except Exception as e:
                error_result = ToolOutput(
                    tool_name=tool_request.name,
                    command=[],
                    return_code=-1,
                    stdout="",
                    stderr=f"Internal error: {str(e)}",
                    output_file_paths=[],
                    success=False
                )
                results.append(error_result)
                logger.exception(f"Internal error processing tool {tool_request.name}")

        # Determine overall status
        all_success = all(result.success for result in results)
        any_success = any(result.success for result in results)

        if all_success:
            status = "success"
            message = "All tools executed successfully."
        elif any_success:
            status = "partial_failure"
            message = "Some tools failed to execute."
        else:
            status = "failed"
            message = "All tools failed to execute."

        scan_response = ScanResponse(
            scan_id=scan_request.scan_id,
            target=scan_request.target,
            target_domain=target_domain,
            results=results,
            message=message,
            status=status
        )

        # Use model_dump() instead of dict() for Pydantic v2
        return jsonify(scan_response.model_dump()), 200

    except Exception as e:
        logger.exception("A critical error occurred processing the scan request")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)