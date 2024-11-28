import json
import logging
import os
import re
import yaml


log_path = 'logs/builder_logs.log'

log_dir = os.path.dirname(log_path)

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    level=logging.NOTSET,  # Minimum severity level to log
    # Log message format
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),  # Log to a file
        logging.StreamHandler()  # Also display in the console
    ]
)


class api_schema_translator:

    REQUIRED_COMPONENTS = ["openapi", "info", "servers", "paths", "components"]

    def __init__(self, api_path):
        self.api_path = os.path.abspath(api_path)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        self.api_info = self.__load_api_file(self.api_path)
        self.__validate_api_info()

    def build(self, api_name, ip, port):
        if not self.__validate_ip_port(ip, port):
            self.logger.error("Invalid IP or port. Aborting build.")
            return

        api_data = {
            "apiName": self.api_info["info"].get("title", api_name),
            "aefProfiles": self.__build_aef_profiles(ip, port),
            "description": self.api_info["info"].get("description", "No description provided"),
            "supportedFeatures": "fffff",
            "shareableInfo": {
                "isShareable": True,
                "capifProvDoms": ["string"]
            },
            "serviceAPICategory": "string",
            "apiSuppFeats": "fffff",
            "pubApiPath": {
                "ccfIds": ["string"]
            },
            "ccfId": "string"
        }

        with open(f"{api_name}.json", "w") as outfile:
            json.dump(api_data, outfile, indent=4)
        self.logger.info(f"API description saved to {api_name}.json")

    def __load_api_file(self, api_file: str):
        """Loads the Swagger API configuration file and converts YAML to JSON format if necessary."""
        try:
            with open(api_file, 'r') as file:
                if api_file.endswith('.yaml') or api_file.endswith('.yml'):
                    yaml_content = yaml.safe_load(file)
                    return json.loads(json.dumps(yaml_content))  # Convert YAML to JSON format
                elif api_file.endswith('.json'):
                    return json.load(file)
                else:
                    self.logger.warning(
                        f"Unsupported file extension for {api_file}. Only .yaml, .yml, and .json are supported.")
                    return {}
        except FileNotFoundError:
            self.logger.warning(
                f"Configuration file {api_file} not found. Using defaults or environment variables.")
            return {}
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            self.logger.error(
                f"Error parsing the configuration file {api_file}: {e}")
            return {}

    def __validate_api_info(self):
        """Validates that all required components are present in the API specification."""
        missing_components = [comp for comp in self.REQUIRED_COMPONENTS if comp not in self.api_info]
        if missing_components:
            self.logger.warning(f"Missing components in API specification: {', '.join(missing_components)}")
        else:
            self.logger.info("All required components are present in the API specification.")

    def __build_aef_profiles(self, ip, port):
        """Builds the aefProfiles section based on the paths and components in the API info."""
        aef_profiles = []

        resources = []
        for path, methods in self.api_info.get("paths", {}).items():
            for method, details in methods.items():
                resource = {
                    "resourceName": details.get("summary", "Unnamed Resource"),
                    "commType": "REQUEST_RESPONSE",
                    "uri": path,
                    "custOpName": f"http_{method}",
                    "operations": [method.upper()],
                    "description": details.get("description", "")
                }
                resources.append(resource)

        # Example profile creation based on paths, customize as needed
        aef_profile = {
            "aefId": "",  # Placeholder AEF ID
            "versions": [
                {
                    "apiVersion": "v1",
                    "expiry": "2100-11-30T10:32:02.004Z",
                    "resources": resources,
                    "custOperations": [
                        {
                            "commType": "REQUEST_RESPONSE",
                            "custOpName": "string",
                            "operations": ["POST"],
                            "description": "string"
                        },
                        {
                            "commType": "REQUEST_RESPONSE",
                            "custOpName": "check-authentication",
                            "operations": [
                                "POST"
                            ],
                            "description": "Check authentication request."
                        },
                        {
                            "commType": "REQUEST_RESPONSE",
                            "custOpName": "revoke-authentication",
                            "operations": [
                                "POST"
                            ],
                            "description": "Revoke authorization for service APIs."
                        }
                    ]
                }
            ],
            "protocol": "HTTP_1_1",
            "dataFormat": "JSON",
            "securityMethods": ["Oauth"],
            "interfaceDescriptions": [
                {
                    "ipv4Addr": ip,
                    "port": port,
                    "securityMethods": ["Oauth"]
                }
            ]
        }
        aef_profiles.append(aef_profile)

        return aef_profiles

    def __validate_ip_port(self, ip, port):
        """Validates that the IP and port have the correct format."""
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

        # Validate IP
        if not ip_pattern.match(ip):
            self.logger.warning(f"Invalid IP format: {ip}. Expected IPv4 format.")
            return False

        # Validate each octet in the IP address
        if any(int(octet) > 255 or int(octet) < 0 for octet in ip.split(".")):
            self.logger.warning(f"IP address out of range: {ip}. Each octet should be between 0 and 255.")
            return False

        # Validate Port
        if not (1 <= port <= 65535):
            self.logger.warning(f"Invalid port number: {port}. Port should be between 1 and 65535.")
            return False

        self.logger.info("IP and port have correct format.")
        return True
