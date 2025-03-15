import requests
import json

# Graylog API credentials
GRAYLOG_BASE_URL = "http://44.210.84.4:9000/api"
USERNAME = "user"
PASSWORD = "yourpassword"  # Replace with the actual password or use an API token

# Headers for API request
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-Requested-By": "cli"  # Required for API authentication
}

# Authenticate and get session
session = requests.Session()
session.auth = (USERNAME, PASSWORD)

# Endpoints
INPUTS_ENDPOINT = f"{GRAYLOG_BASE_URL}/system/inputs"
INDEX_SETS_ENDPOINT = f"{GRAYLOG_BASE_URL}/system/indices/index_sets"
STREAMS_ENDPOINT = f"{GRAYLOG_BASE_URL}/streams"

# Input payloads
input_payloads = [
    {
        "title": "UDP Syslog 514",
        "global": True,
        "type": "org.graylog2.inputs.syslog.udp.SyslogUDPInput",
        "configuration": {
            "port": 514,
            "bind_address": "0.0.0.0",
            "recv_buffer_size": 262144,
            "allow_override_date": True,
            "store_full_message": True,
            "expand_structured_data": False,
            "force_rdns": False,
            "charset_name": "UTF-8"
        }
    }
]

# Index set payloads
index_set_payloads = [
    {
        "title": "Linux alerts",
        "description": "Tracks all Linux commands executed via rsyslog",
        "index_prefix": "linux",
        "index_analyzer": "standard",
        "shards": 1,
        "replicas": 0,
        "index_optimization_max_num_segments": 1,
        "index_optimization_disabled": True,
        "field_type_refresh_interval": 5000,
        "writable": True,
        "default": False,
        "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.MessageCountRotationStrategy",
        "rotation_strategy": {
            "type": "org.graylog2.indexer.rotation.strategies.MessageCountRotationStrategyConfig",
            "max_docs_per_index": 20000000
        },
        "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
        "retention_strategy": {
            "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
            "max_number_of_indices": 20
        }
    }
]

# Stream payloads (index_set_id will be updated dynamically)
stream_payloads = [
    {
        "title": "Linux-cmds",
        "description": "Stream for Linux commands executed via rsyslog",
        "index_set_id": None,  # Will be set dynamically after index set creation
        "rules": [
            {
                "field": "message",
                "value": "EXECVE",
                "type": 6,
                "inverted": False
            },
            {
                "field": "message",
                "value": "argc",
                "type": 6,
                "inverted": False
            }
        ],
        "matching_type": "AND",
        "remove_matches_from_default_stream": True
    },

    {
        "title": "Auth-logs",
        "description": "Stream for Linux authentication logs",
        "index_set_id": None,
        "rules": [
            {
                "field": "message",
                "value": "auth",
                "type": 6,
                "inverted": False
            }
        ],
        "matching_type": "AND",
        "remove_matches_from_default_stream": True
    }
]

# Function to send a POST request
def send_post_request(endpoint, payload, item_type):
    print(f"Sending {item_type} payload: {payload['title']}")
    response = session.post(endpoint, headers=HEADERS, data=json.dumps(payload))
    # Treat both 200 and 201 as success
    if response.status_code in [200, 201]:
        print(f"{item_type} created successfully!")
        print(response.json())
        # If creating a stream, start it automatically
        if item_type == "Stream":
            response_json = response.json()
            # Check for both 'id' and 'stream_id' to handle different Graylog versions
            stream_id = response_json.get("id") or response_json.get("stream_id")
            if not stream_id:
                print("Error: Could not find 'id' or 'stream_id' in stream creation response.")
                print("---")
                return response_json
            start_stream_endpoint = f"{STREAMS_ENDPOINT}/{stream_id}/resume"
            start_response = session.post(start_stream_endpoint, headers=HEADERS)
            if start_response.status_code in [200, 204]:
                print(f"Stream {payload['title']} started successfully!")
            else:
                print(f"Failed to start stream. Status code: {start_response.status_code}")
                print(start_response.text)
        return response.json()  # Return the response for further use
    else:
        print(f"Failed to create {item_type}. Status code: {response.status_code}")
        print(response.text)
    print("---")
    return None

# Create inputs and capture the input_id (no longer used for stream rules)
input_id = None
for payload in input_payloads:
    response = send_post_request(INPUTS_ENDPOINT, payload, "Input")
    if response:
        input_id = response["id"]

# Create index sets and capture the index_set_id
index_set_id = None
for payload in index_set_payloads:
    response = send_post_request(INDEX_SETS_ENDPOINT, payload, "Index set")
    if response:
        index_set_id = response["id"]

# Update stream payloads with the correct index_set_id
if index_set_id:
    for payload in stream_payloads:
        payload["index_set_id"] = index_set_id
else:
    print("Error: Could not retrieve index_set_id. Stream creation will fail.")
    exit(1)

# Create streams
for payload in stream_payloads:
    send_post_request(STREAMS_ENDPOINT, payload, "Stream")