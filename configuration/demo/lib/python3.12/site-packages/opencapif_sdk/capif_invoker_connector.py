import os
import logging
import shutil
from requests.auth import HTTPBasicAuth
import urllib3
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (
    dump_certificate_request,
    dump_privatekey,
    PKey,
    TYPE_RSA,
    X509Req
)
import requests
import json
import warnings
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


class capif_invoker_connector:
    """
    Τhis class is responsbile for onboarding an Invoker (ex. a Invoker) to CAPIF
    """
    def __init__(self, config_file: str):

        config_file = os.path.abspath(config_file)
        # Load configuration from file if necessary
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

        self.logger.info("Initializing capif_invoker_connector")

        # Assign values from environment variables or JSON configuration
        invoker_config = config.get('invoker', {})
        invoker_general_folder = os.path.abspath(os.getenv('invoker_folder', invoker_config.get('invoker_folder', '')).strip())

        capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
        register_host = os.getenv('REGISTER_HOST', config.get('register_host', '')).strip()
        capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
        capif_register_port = str(os.getenv('CAPIF_REGISTER_PORT', config.get('capif_register_port', '')).strip())
        capif_username = os.getenv('CAPIF_USERNAME', config.get('capif_username', '')).strip()
        capif_invoker_password = os.getenv('CAPIF_PASSWORD', config.get('capif_password', '')).strip()
        
        capif_callback_url = os.getenv('INVOKER_CAPIF_CALLBACK_URL', invoker_config.get('capif_callback_url', '')).strip()
        supported_features = os.getenv('INVOKER_FOLDER', invoker_config.get('supported_features', '')).strip()
        check_authentication_data = invoker_config.get('check_authentication_data', {})
        self.check_authentication = {
            "ip": os.getenv('INVOKER_CHECK_AUTHENTICATION_DATA_IP', check_authentication_data.get('ip', '')).strip(),
            "port":  os.getenv('INVOKER_CHECK_AUTHENTICATION_DATA_PORT', check_authentication_data.get('port', '')).strip()
        } 

        # Extract CSR configuration from the JSON
        csr_config = invoker_config.get('cert_generation', {})
        csr_common_name = os.getenv('INVOKER_CSR_COMMON_NAME', csr_config.get('csr_common_name', '')).strip()
        csr_organizational_unit = os.getenv('INVOKER_CSR_ORGANIZATIONAL_UNIT', csr_config.get('csr_organizational_unit', '')).strip()
        csr_organization = os.getenv('INVOKER_CSR_ORGANIZATION', csr_config.get('csr_organization', '')).strip()
        csr_locality = os.getenv('INVOKER_CSR_LOCALITY', csr_config.get('csr_locality', '')).strip()
        csr_state_or_province_name = os.getenv('INVOKER_CSR_STATE_OR_PROVINCE_NAME', csr_config.get('csr_state_or_province_name', '')).strip()
        csr_country_name = os.getenv('INVOKER_CSR_COUNTRY_NAME', csr_config.get('csr_country_name', '')).strip()
        csr_email_address = os.getenv('INVOKER_CSR_EMAIL_ADDRESS', csr_config.get('csr_email_address', '')).strip()

        # Define the invoker folder path and create it if it doesn't exist
        self.invoker_folder = os.path.join(invoker_general_folder, capif_username)
        os.makedirs(self.invoker_folder, exist_ok=True)
        self.supported_features = supported_features        

        # Configure URLs for CAPIF HTTPS and register services
        if len(capif_https_port) == 0 or int(capif_https_port) == 443:
            self.capif_https_url = "https://" + capif_host.strip() + "/"
        else:
            self.capif_https_url = "https://" + capif_host.strip() + ":" + capif_https_port.strip() + "/"

        if len(capif_register_port) == 0:
            self.capif_register_url = "https://" + register_host.strip() + ":8084/"
        else:
            self.capif_register_url = "https://" + register_host.strip() + ":" + capif_register_port.strip() + "/"

        # Ensure the callback URL ends with a slash
        self.capif_callback_url = self.__add_trailing_slash_to_url_if_missing(capif_callback_url.strip())

        # Assign final attributes for CAPIF connection and CSR details
        self.capif_username = capif_username
        self.capif_invoker_password = capif_invoker_password

        self.csr_common_name = "invoker_" + csr_common_name
        self.csr_organizational_unit = csr_organizational_unit
        self.csr_organization = csr_organization
        self.csr_locality = csr_locality
        self.csr_state_or_province_name = csr_state_or_province_name
        self.csr_country_name = csr_country_name
        self.csr_email_address = csr_email_address
        self.invoker_capif_details_filename = "capif_api_security_context_details-" + self.capif_username + ".json"

        path = os.path.join(
            self.invoker_folder,
            self.invoker_capif_details_filename
        )
        if os.path.exists(path):
            self.invoker_capif_details = self.__load_invoker_api_details()

        self.logger.info("capif_invoker_connector initialized with the JSON parameters")

    def __load_config_file(self, config_file: str):
        """Loads the configuration file."""
        try:
            with open(config_file, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            self.logger.warning(
                f"Configuration file {config_file} not found. Using defaults or environment variables.")
            return {}

    def __add_trailing_slash_to_url_if_missing(self, url):
        if url[len(url) - 1] != "/":
            url = url + "/"
        return url

    def onboard_invoker(self) -> None:
        self.logger.info("Registering and onboarding Invoker")
        try:
            public_key = self.__create_private_and_public_keys()
            capif_postauth_info = self.__save_ca_root_and_get_auth()
            capif_onboarding_url = capif_postauth_info["ccf_onboarding_url"]
            capif_discover_url = capif_postauth_info["ccf_discover_url"]
            capif_access_token = capif_postauth_info["access_token"]
            api_invoker_id = self.__onboard_invoker_and_create_certificate(
                public_key, capif_onboarding_url, capif_access_token
            )
            self.__write_to_file(api_invoker_id, capif_discover_url)
            self.logger.info("Invoker registered and onboarded successfully")
        except Exception as e:
            self.logger.error(
                f"Error during Invoker registration and onboarding: {e}")
            raise

    def __load_invoker_api_details(self):
        self.logger.info("Loading Invoker API details")
        path = os.path.join(
            self.invoker_folder,
            self.invoker_capif_details_filename
        )
        with open(
            path, "r"
        ) as openfile:
            return json.load(openfile)

    def __offboard_Invoker(self) -> None:
        self.logger.info("Offboarding Invoker")
        try:
            invoker_capif_details = self.__load_invoker_api_details()
            url = (
                self.capif_https_url
                + "api-invoker-management/v1/onboardedInvokers/"
                + invoker_capif_details["api_invoker_id"]
            )

            signed_key_crt_path = os.path.join(
                self.invoker_folder,
                invoker_capif_details["user_name"] + ".crt"
            )

            private_key_path = os.path.join(
                self.invoker_folder,
                "private.key"
            )

            path = os.path.join(
                self.invoker_folder,
                "ca.crt"
            )
            response = requests.request(
                "DELETE",
                url,
                cert=(signed_key_crt_path, private_key_path),
                verify=path,
            )
            response.raise_for_status()
            self.logger.info("Invoker offboarded successfully")
        except Exception as e:
            self.logger.error(
                f"Error during Invoker offboarding: {e} - Response: {response.text}")
            raise

    def offboard_invoker(self) -> None:
        self.logger.info("Offboarding and deregistering Invoker")
        try:
            self.__offboard_Invoker()
            self.__remove_files()
            self.logger.info(
                "Invoker offboarded and deregistered successfully")
        except Exception as e:
            self.logger.error(
                f"Error during Invoker offboarding and deregistering: {e}")
            raise

    def __create_private_and_public_keys(self) -> str:
        self.logger.info(
            "Creating private and public keys for the Invoker cert")
        try:
            private_key_path = os.path.join(self.invoker_folder, "private.key")

            csr_file_path = os.path.join(self.invoker_folder, "cert_req.csr")

            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            req = X509Req()
            req.get_subject().CN = self.csr_common_name
            req.get_subject().O = self.csr_organization
            req.get_subject().OU = self.csr_organizational_unit
            req.get_subject().L = self.csr_locality
            req.get_subject().ST = self.csr_state_or_province_name
            req.get_subject().C = self.csr_country_name
            req.get_subject().emailAddress = self.csr_email_address
            req.set_pubkey(key)
            req.sign(key, "sha256")

            with open(csr_file_path, "wb+") as f:
                f.write(dump_certificate_request(FILETYPE_PEM, req))
                public_key = dump_certificate_request(FILETYPE_PEM, req)
            with open(private_key_path, "wb+") as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))

            self.logger.info("Keys created successfully")
            return public_key
        except Exception as e:
            self.logger.error(f"Error during key creation: {e}")
            raise

    def __remove_files(self):
        self.logger.info("Removing files generated")
        try:
            folder_path = self.invoker_folder

            if os.path.exists(folder_path):
                # Removes all the content within the folder
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        os.remove(os.path.join(root, file))
                    for dir in dirs:
                        shutil.rmtree(os.path.join(root, dir))
                os.rmdir(folder_path)
                self.logger.info(
                    f"All contents in {folder_path} removed successfully")
            else:
                self.logger.warning(f"Folder {folder_path} does not exist.")
        except Exception as e:
            self.logger.error(f"Error during removing folder contents: {e}")
            raise

    def __save_ca_root_and_get_auth(self):
        self.logger.info(
            "Saving CAPIF CA root file and getting auth token with user and password given by the CAPIF administrator")
        try:
            url = self.capif_register_url + "getauth"

            response = requests.request(
                "GET",
                url,
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth(self.capif_username,
                                   self.capif_invoker_password),
                verify=False,
            )

            response.raise_for_status()
            response_payload = json.loads(response.text)
            ca_root_file_path = os.path.join(self.invoker_folder, "ca.crt")
            ca_root_file = open(ca_root_file_path, "wb+")
            ca_root_file.write(bytes(response_payload["ca_root"], "utf-8"))
            self.logger.info(
                "CAPIF CA root file saved and auth token obtained successfully")
            return response_payload
        except Exception as e:
            self.logger.error(
                f"Error during saving CAPIF CA root file and getting auth token: {e} - Response: {response.text}")
            raise

    def __onboard_invoker_and_create_certificate(
        self, public_key, capif_onboarding_url, capif_access_token
    ):
        self.logger.info(
            "Onboarding Invoker to CAPIF and creating signed certificate by giving our public key to CAPIF")
        try:
            url = self.capif_https_url + capif_onboarding_url
            payload_dict = {
                "notificationDestination": self.capif_callback_url,
                "supportedFeatures": self.supported_features,
                "apiInvokerInformation": self.csr_common_name,
                "websockNotifConfig": {
                    "requestWebsocketUri": True,
                    "websocketUri": "websocketUri",
                },
                "onboardingInformation": {"apiInvokerPublicKey": str(public_key, "utf-8")},
                "requestTestNotification": True,
            }
            payload = json.dumps(payload_dict)
            headers = {
                "Authorization": "Bearer {}".format(capif_access_token),
                "Content-Type": "application/json",
            }
            pathca = os.path.join(self.invoker_folder, "ca.crt")
            response = requests.request(
                "POST",
                url,
                headers=headers,
                data=payload,
                verify=pathca,
            )
            response.raise_for_status()
            response_payload = json.loads(response.text)
            name = self.capif_username+".crt"
            pathcsr = os.path.join(self.invoker_folder, name)
            certification_file = open(
                pathcsr, "wb"
            )
            certification_file.write(
                bytes(
                    response_payload["onboardingInformation"]["apiInvokerCertificate"],
                    "utf-8",
                )
            )
            certification_file.close()
            self.logger.info(
                "Invoker onboarded and signed certificate created successfully")
            return response_payload["apiInvokerId"]
        except Exception as e:
            self.logger.error(
                f"Error during onboarding Invoker to CAPIF: {e} - Response: {response.text}")
            raise

    def __write_to_file(self, api_invoker_id, discover_services_url):
        self.logger.info(
            "Writing API invoker ID and service discovery URL to file")
        path = os.path.join(self.invoker_folder,
                            self.invoker_capif_details_filename)
        try:
            with open(
                path, "w"
            ) as outfile:
                json.dump(
                    {
                        "user_name": self.capif_username,
                        "api_invoker_id": api_invoker_id,
                        "discover_services_url": discover_services_url,
                    },
                    outfile,
                )
            self.logger.info(
                "API invoker ID and service discovery URL written to file successfully")
        except Exception as e:
            self.logger.error(f"Error during writing to file: {e}")
            raise

    def update_invoker(self):
        self.logger.info("Updating Invoker")
        try:

            capif_postauth_info = self.__save_ca_root_and_get_auth()
            capif_onboarding_url = capif_postauth_info["ccf_onboarding_url"]
            capif_access_token = capif_postauth_info["access_token"]
            path = self.invoker_folder + "/cert_req.csr"
            with open(path, "rb") as file:
                public_key = file.read()

            self.__update_invoker_to_capif_and_create_the_signed_certificate(
                public_key, capif_onboarding_url, capif_access_token
            )

            self.logger.info("Invoker updated successfully")
        except Exception as e:
            self.logger.error(f"Error during Invoker updating Invoker: {e}")
            raise

    def __update_invoker_to_capif_and_create_the_signed_certificate(
        self, public_key, capif_onboarding_url, capif_access_token
    ):
        self.logger.info(
            "Updating Invoker to CAPIF and creating signed certificate by giving our public key to CAPIF")
        try:
            path = self.invoker_folder + "/" + self.invoker_capif_details_filename

            with open(path, "r") as file:
                invoker_details = file.read()

            invoker_details = json.loads(invoker_details)

            invokerid = invoker_details["api_invoker_id"]
            url = self.capif_https_url + capif_onboarding_url + "/" + invokerid
            payload_dict = {
                "notificationDestination": self.capif_callback_url,
                "supportedFeatures": self.supported_features,
                "apiInvokerInformation": self.csr_common_name,
                "websockNotifConfig": {
                    "requestWebsocketUri": True,
                    "websocketUri": "websocketUri",
                },
                "onboardingInformation": {"apiInvokerPublicKey": str(public_key, "utf-8")},
                "requestTestNotification": True,
            }
            payload = json.dumps(payload_dict)
            headers = {
                "Authorization": "Bearer {}".format(capif_access_token),
                "Content-Type": "application/json",
            }
            signed_key_crt_path = os.path.join(
                self.invoker_folder,
                self.capif_username + ".crt"
            )

            private_key_path = os.path.join(
                self.invoker_folder,
                "private.key"
            )
            pathca = os.path.join(self.invoker_folder, "ca.crt")
            response = requests.request(
                "PUT",
                url,
                headers=headers,
                data=payload,
                cert=(signed_key_crt_path, private_key_path),
                verify=pathca,
            )

            response.raise_for_status()

            self.logger.info(
                "Invoker updated and signed certificate updated successfully")

        except Exception as e:
            self.logger.error(
                f"Error during updating Invoker to CAPIF: {e} - Response: {response.text}")
            raise

    

