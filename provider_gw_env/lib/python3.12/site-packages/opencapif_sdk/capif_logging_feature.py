import os
import logging
import urllib3
import requests
import json
import warnings
import jwt
from OpenSSL import crypto
from jwt.exceptions import InvalidTokenError
from requests.exceptions import RequestsDependencyWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
# noqa: E501
# Basic configuration of the logger functionality

log_path = 'logs/sdk_logs.log'

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


class capif_logging_feature:

    def __init__(self, config_file: str):
        """
        Initializes the CAPIFProvider connector with the parameters specified in the configuration file.
        """
        # Load configuration from file if necessary
        config_file = os.path.abspath(config_file)
        self.config_path = os.path.dirname(config_file)+"/"
        config = self.__load_config_file(config_file)
        debug_mode = os.getenv('DEBUG_MODE', config.get('debug_mode', 'False')).strip().lower()
        if debug_mode == "false":
            debug_mode = False
        else:
            debug_mode = True

        # Initialize logger for this class
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug_mode:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.WARNING)

        # Set logging level for urllib based on debug_mode
        urllib_logger = logging.getLogger("urllib3")
        if not debug_mode:
            urllib_logger.setLevel(logging.WARNING)
        else:
            urllib_logger.setLevel(logging.DEBUG)

        try:
            # Retrieve provider configuration from JSON or environment variables
            provider_config = config.get('provider', {})
            provider_general_folder = os.path.abspath(
                os.getenv('PROVIDER_FOLDER', provider_config.get('provider_folder', '')).strip())

            capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
            capif_register_host = os.getenv('REGISTER_HOST', config.get('register_host', '')).strip()
            capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
            capif_register_port = str(os.getenv('CAPIF_REGISTER_PORT', config.get('capif_register_port', '')).strip())
            capif_provider_username = os.getenv('CAPIF_USERNAME', config.get('capif_username', '')).strip()
            capif_provider_password = os.getenv('CAPIF_PASSWORD', config.get('capif_password', '')).strip()

            # Get CSR (Certificate Signing Request) details from config or environment variables
            cert_generation = provider_config.get('cert_generation', {})
            csr_common_name = os.getenv('PROVIDER_CSR_COMMON_NAME', cert_generation.get('csr_common_name', '')).strip()
            csr_organizational_unit = os.getenv('PROVIDER_CSR_ORGANIZATIONAL_UNIT', cert_generation.get('csr_organizational_unit', '')).strip()
            csr_organization = os.getenv('PROVIDER_CSR_ORGANIZATION', cert_generation.get('csr_organization', '')).strip()
            csr_locality = os.getenv('PROVIDER_CSR_LOCALITY', cert_generation.get('csr_locality', '')).strip()
            csr_state_or_province_name = os.getenv('PROVIDER_CSR_STATE_OR_PROVINCE_NAME', cert_generation.get('csr_state_or_province_name', '')).strip()
            csr_country_name = os.getenv('PROVIDER_CSR_COUNTRY_NAME', cert_generation.get('csr_country_name', '')).strip()
            csr_email_address = os.getenv('PROVIDER_CSR_EMAIL_ADDRESS', cert_generation.get('csr_email_address', '')).strip()

            # Retrieve provider specific values (APFs, AEFs)
            supported_features = os.getenv('PROVIDER_SUPPORTED_FEATURES', provider_config.get('supported_features', '')).strip()
            if not supported_features:
                supported_features = "0"

            apfs = os.getenv('PROVIDER_APFS', provider_config.get('apfs', '')).strip()
            aefs = os.getenv('PROVIDER_AEFS', provider_config.get('aefs', '')).strip()
            api_description_path = os.path.abspath(os.getenv('PROVIDER_API_DESCRIPTION_PATH', provider_config.get('api_description_path', '')).strip())
            log = os.getenv('PROVIDER_LOG', provider_config.get('log', ''))

            # Check required fields and log warnings/errors
            if not capif_host:
                self.logger.warning("CAPIF_HOST is not provided; defaulting to an empty string")
            if not capif_provider_username:
                self.logger.error("CAPIF_PROVIDER_USERNAME is required but not provided")
                raise ValueError("CAPIF_PROVIDER_USERNAME is required")

            # Setup the folder to store provider files (e.g., certificates)
            self.provider_folder = os.path.join(provider_general_folder, capif_provider_username)
            os.makedirs(self.provider_folder, exist_ok=True)

            # Set attributes for provider credentials and configuration
            self.capif_host = capif_host.strip()
            self.capif_provider_username = capif_provider_username
            self.capif_provider_password = capif_provider_password
            self.capif_register_host = capif_register_host
            self.capif_register_port = capif_register_port
            self.csr_common_name = csr_common_name
            self.csr_organizational_unit = csr_organizational_unit
            self.csr_organization = csr_organization
            self.csr_locality = csr_locality
            self.csr_state_or_province_name = csr_state_or_province_name
            self.csr_country_name = csr_country_name
            self.csr_email_address = csr_email_address
            self.supported_features = supported_features
            self.aefs = int(aefs)
            self.apfs = int(apfs)

            # Get publish request details from config or environment variables
            publish_req_config = provider_config.get('publish_req', {})
            self.publish_req = {
                "service_api_id": os.getenv('PUBLISH_REQ_SERVICE_API_ID', publish_req_config.get('service_api_id', '')).strip(),
                "publisher_apf_id": os.getenv('PUBLISH_REQ_PUBLISHER_APF_ID', publish_req_config.get('publisher_apf_id', '')).strip(),
                "publisher_aefs_ids": os.getenv('PUBLISH_REQ_PUBLISHER_AEFS_IDS', publish_req_config.get('publisher_aefs_ids', ''))
            }

            # Set the path for the API description file
            self.api_description_path = api_description_path

            # Set the CAPIF HTTPS port and construct CAPIF URLs
            self.capif_https_port = str(capif_https_port)

            self.provider_capif_ids = {}

            path_prov_funcs = os.path.join(self.provider_folder, "provider_capif_ids.json")
            if os.path.exists(path_prov_funcs):
                self.provider_capif_ids = self.__load_provider_api_details()

            path_published = os.path.join(self.provider_folder, "provider_service_ids.json")
            if os.path.exists(path_published):
                self.provider_service_ids = self.__load_config_file(path_published)

            # Construct the CAPIF HTTPS URL
            if len(self.capif_https_port) == 0 or int(self.capif_https_port) == 443:
                self.capif_https_url = f"https://{capif_host.strip()}/"
            else:
                self.capif_https_url = f"https://{capif_host.strip()}:{self.capif_https_port.strip()}/"

            # Construct the CAPIF register URL
            if len(capif_register_port) == 0:
                self.capif_register_url = f"https://{capif_register_host.strip()}:8084/"
            else:
                self.capif_register_url = f"https://{capif_register_host.strip()}:{capif_register_port.strip()}/"

            self.__search_aef_and_api_by_name(log)

            self.log = log

            # Log initialization success message
            self.logger.info("capif_logging_feature initialized with the capif_sdk_config.json parameters")

        except Exception as e:
            # Catch and log any exceptions that occur during initialization
            self.logger.error(f"Error during initialization: {e}")
            raise

    def __search_aef_and_api_by_name(self, log):
        """
        Searches for an AEF and API by name and updates self.api_id with the corresponding ID.

        Args:
            log (dict): A record containing API information, including "apiName".

        Raises:
            KeyError: If "apiName" is not present in the log.
            ValueError: If no ID is associated with the given name.
        """
        # Validate that the log contains the "apiName" field
        if "apiName" not in log:
            raise KeyError("The provided log does not contain 'apiName'.")

        # Retrieve the API name
        name = log["apiName"]

        # Search for the corresponding API ID
        self.api_id = self.provider_service_ids.get(name)

        # Validate that a valid ID was found
        if not self.api_id:
            raise ValueError(f"No ID was found for the API '{name}'.")

    def create_logs(self, aefId, jwt):
        
        api_invoker_id = self._decrypt_jwt(jwt)
        
        path = self.capif_https_url + f"/api-invocation-logs/v1/{aefId}/logs"

        log_entry = {
            "apiId": self.api_id,
            "apiName": self.log["apiName"],
            "apiVersion": self.log["apiVersion"],
            "resourceName": self.log["resourceName"],
            "uri": self.log["uri"],
            "protocol": self.log["protocol"],
            "operation": self.log["operation"],
            "result": self.log["result"]
        }
        
        payload = {
            "aefId": f"{aefId}",
            "apiInvokerId": f"{api_invoker_id}",
            "logs": [log_entry],
            "supportedFeatures": f"{self.supported_features}"
        }
        provider_details = self.__load_provider_api_details()
        AEF_api_prov_func_id = aefId
        aef_number = None
        for key, value in provider_details.items():
            if value == AEF_api_prov_func_id and key.startswith("AEF-"):
                aef_inter = key.split("-")[1]
                # Obtain the aef number
                aef_number = aef_inter.split("_")[0]
                break

        if aef_number is None:
            self.logger.error(
                f"No matching AEF found for publisher_aef_id: {AEF_api_prov_func_id}")
            raise ValueError("Invalid publisher_aef_id")

        cert = (
            os.path.join(self.provider_folder, f"aef-{aef_number}.crt"),
            os.path.join(self.provider_folder,
                         f"AEF-{aef_number}_private_key.key"),
        )

        try:
            response = requests.post(
                url=path,
                json=payload,
                headers={"Content-Type": "application/json"},
                cert=cert,
                verify=os.path.join(self.provider_folder, "ca.crt")
            )

            response.raise_for_status()

            return response.status_code, response.json()

        except Exception as e:
            self.logger.error("Unexpected error: %s", e)
            return None, {"error": f"Unexpected error: {e}"}

    def __load_provider_api_details(self) -> dict:
        """
        Loads NEF API details from the CAPIF provider details JSON file.

        :return: A dictionary containing NEF API details.
        :raises FileNotFoundError: If the CAPIF provider details file is not found.
        :raises json.JSONDecodeError: If there is an error decoding the JSON file.
        """
        file_path = os.path.join(self.provider_folder,
                                 "provider_capif_ids.json")

        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(
                f"Error decoding JSON from file {file_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(
                f"Unexpected error while loading NEF API details: {e}")
            raise

    def __load_config_file(self, config_file: str):
        """Carga el archivo de configuración."""
        try:
            with open(config_file, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            self.logger.warning(
                f"Configuration file {config_file} not found. Using defaults or environment variables.")
            return {}
    
    def _decrypt_jwt(self, jwt_token):
        """
        Decrypts the given JWT using the provided certificate.

        :param jwt_token: The JWT to decrypt.
        :return: The payload of the JWT if it is valid.
        :raises: InvalidTokenError if the JWT is invalid or cannot be decrypted.
        """
        try:
            # Path to the certificate
            path = os.path.join(self.provider_folder, "capif_cert_server.pem")

            # Ensure the certificate file exists
            if not os.path.exists(path):
                raise FileNotFoundError(f"Certificate file not found at {path}")

            # Load the public key from the certificate
            with open(path, "r") as cert_file:
                cert = cert_file.read()

            # Decode the JWT using the public key
            crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            pubKeyObject = crtObj.get_pubkey()
            pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
            payload = jwt.decode(jwt_token, pubKeyString, algorithms=["RS256"])

            for key, value in payload.items():
                if key == "sub":
                    return value

        except InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid JWT token: {e}")

        except Exception as e:
            raise Exception(f"An error occurred while decrypting the JWT: {e}")
        
