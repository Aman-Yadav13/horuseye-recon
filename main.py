from flask import Flask, request, jsonify
import logging
from app.models import ScanRequest
from tasks import run_recon_scan
import os, json

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/scan', methods=['POST'])
def submit_scan():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        scan_request = ScanRequest(**data)
        run_recon_scan.delay(scan_request.model_dump())

        logger.info(f"Recon scan job queued for target {scan_request.target} (ID: {scan_request.scan_id})")
        return jsonify({"message": "Scan job accepted", "scan_id": scan_request.scan_id}), 202

    except Exception as e:
        logger.exception("Error queuing recon scan")
        return jsonify({"error": str(e)}), 500

@app.route('/results/<string:scan_id>', methods=['GET'])
def get_results(scan_id):
    path = os.path.join("/app", "outputs", scan_id, "final_results.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return jsonify(json.load(f)), 200
    else:
        return jsonify({"status": "pending", "message": "Scan still in progress"}), 202

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
