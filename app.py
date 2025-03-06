import json
import logging
import time
from flask import Flask, jsonify, request
from prometheus_client import Counter, Histogram, generate_latest
from pysnmp.hlapi import *
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize Prometheus metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['endpoint'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration', ['endpoint'])

@app.before_request
def before_request():
    REQUEST_COUNT.labels(endpoint=request.endpoint).inc()
    request.start_time = time.time()

@app.after_request
def after_request(response):
    duration = time.time() - request.start_time
    REQUEST_DURATION.labels(endpoint=request.endpoint).observe(duration)
    return response

# Metrics Endpoint for Prometheus
@app.route('/metrics', methods=['GET'])
def metrics():
    logger.debug("Metrics endpoint hit")
    return generate_latest(), 200, {'content_type': 'text/plain'}

# Health Check Endpoint
@app.route('/health', methods=['GET'])
def health():
    logger.debug("Health endpoint hit")
    return "OK", 200, {'content_type': 'text/plain'}

# Load SNMP credentials from credentials.json
def load_snmp_credentials():
    try:
        with open('credentials.json') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error("credentials.json file not found!")
        return {}
    except json.JSONDecodeError:
        logger.error("Invalid JSON format in credentials.json!")
        return {}

credentials = load_snmp_credentials()

# # Define the SNMP trap request model
# class SNMPTrapRequest:
#     def __init__(self, source, severity, timestamp, message, application, region):
#         self.source = source
#         self.severity = severity
#         self.timestamp = timestamp
#         self.message = message
#         self.application = application
#         self.region = region

# Define the SNMP trap request model
class SNMPTrapRequest:
    def __init__(self, sid, search_name, app, owner, results_link, result):
        self.sid = sid
        self.search_name = search_name
        self.app = app
        self.owner = owner
        self.results_link = results_link
        self.result = result

    @classmethod
    def from_json(cls, data):
        return cls(
            sid=data.get('sid'),
            search_name=data.get('search_name'),
            app=data.get('app'),
            owner=data.get('owner'),
            results_link=data.get('results_link'),
            result=data.get('result', {})
        )

# Function to send SNMP trap asynchronously
async def send_snmp_trap(oids):
    """Send SNMP trap asynchronously."""
    logger.debug(f"Preparing to send SNMP trap with OIDs: {oids}")
    
    # Use 'public' community string for SNMPv2c for testing
    community_string = "public"

    # Load credentials for SNMPv3
    snmpv3_user = credentials.get('snmpv3_user', 'default_user')
    auth_password = credentials.get('auth_password', 'default_password')
    priv_password = credentials.get('priv_password', 'default_priv_password')
    auth_protocol = credentials.get('auth_protocol', 'SHA')
    priv_protocol = credentials.get('priv_protocol', 'AES')
    snmp_target_ip = credentials.get('snmp_target_ip', '127.0.0.1')
    snmp_target_port = credentials.get('snmp_target_port', 162)

    logger.debug("SNMPv2c credentials loaded successfully")

    # Configure SNMPv3 settings
    if auth_protocol == "SHA":
        auth_protocol = usmHMACSHAAuthProtocol
    elif auth_protocol == "MD5":
        auth_protocol = usmHMACMD5AuthProtocol
    else:
        logger.error("Invalid authentication protocol")
        return {"status": "error", "message": "Invalid authentication protocol"}

    if priv_protocol == "AES":
        priv_protocol = usmAesCfb128Protocol
    elif priv_protocol == "DES":
        priv_protocol = usmDESPrivProtocol
    else:
        logger.error("Invalid privacy protocol")
        return {"status": "error", "message": "Invalid privacy protocol"}

    # Configure SNMPv3 settings
    auth_data = UsmUserData(
        userName=snmpv3_user,
        authKey=auth_password,
        privKey=priv_password,
        authProtocol=auth_protocol,
        privProtocol=priv_protocol
    )

    # SNMP target configuration
    TARGETS = []

    # SNMPv2c Target
    TARGETS.append(
        (
            CommunityData(community_string),
            await UdpTransportTarget.create((snmp_target_ip, snmp_target_port)),
            ContextData(),
        )
    )

    # SNMPv3 Target
    TARGETS.append(
        (
            auth_data,
            await UdpTransportTarget.create((snmp_target_ip, snmp_target_port)),
            ContextData(),
        )
    )

    snmpEngine = SnmpEngine()

    # Send SNMP trap
    try:
        logger.debug("Sending SNMP trap...")

        for communityData, transportTarget, contextData in TARGETS:
            (
                errorIndication,
                errorStatus,
                errorIndex,
                varBindTable,
            ) = await send_notification(
                snmpEngine,
                communityData,
                transportTarget,
                contextData,
                "inform",  # NotifyType
                NotificationType(ObjectIdentity("SNMPv2-MIB", "coldStart")).add_varbinds(*oids),
            )
            logger.debug("SNMP notification response received.")
            if errorIndication:
                logger.error(f"Notification not sent: {errorIndication}")
            elif errorStatus:
                logger.error(f"Notification Receiver returned error: {errorStatus} @ {errorIndex}")
            else:
                logger.info("Notification delivered:")
                for name, val in varBindTable:
                    logger.info(f"{name.prettyPrint()} = {val.prettyPrint()}")

    except Exception as e:
        logger.error(f"Exception occurred while sending SNMP trap: {str(e)}")
        return {"status": "error", "message": f"Exception occurred: {str(e)}"}

# Flask POST route to send SNMP traps
@app.route('/send_snmp_trap/', methods=['POST'])
def api_send_snmp_trap():
    try:
        request_data = request.get_json()
        
        logger.debug(f"Received SNMP Trap Request Data: {request_data}")

        trap_request = SNMPTrapRequest.from_json(request_data)
        result_data = trap_request.result

        oids = [
            ("1.3.6.1.4.1.12345.1.2.1", OctetString(trap_request.sid or "N/A")),
            ("1.3.6.1.4.1.12345.1.2.2", OctetString(trap_request.search_name or "N/A")),
            ("1.3.6.1.4.1.12345.1.2.3", OctetString(trap_request.app or "N/A")),
            ("1.3.6.1.4.1.12345.1.2.4", OctetString(trap_request.owner or "N/A")),
            ("1.3.6.1.4.1.12345.1.2.5", OctetString(trap_request.results_link or "N/A")),
            ("1.3.6.1.4.1.12345.1.2.6", OctetString(result_data.get("hostname", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.7", OctetString(result_data.get("index", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.8", OctetString(result_data.get("level", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.9", OctetString(result_data.get("location", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.10", OctetString(result_data.get("message", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.11", OctetString(result_data.get("operation", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.12", OctetString(result_data.get("requestURL", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.13", OctetString(result_data.get("service", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.14", OctetString(result_data.get("source", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.15", OctetString(result_data.get("sourcetype", "N/A"))),
            ("1.3.6.1.4.1.12345.1.2.16", OctetString(result_data.get("time", "N/A")))
        ]

        logger.debug(f"SNMP trap request OIDs prepared: {oids}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_snmp_trap(oids))

        return jsonify({"status": "success", "message": "SNMP Trap sent successfully"})

    except Exception as e:
        logger.error(f"Error occurred during SNMP trap sending: {str(e)}")
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"})

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000, threaded=True)
