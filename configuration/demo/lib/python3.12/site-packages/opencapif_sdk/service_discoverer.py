from requests.exceptions import RequestsDependencyWarning
import warnings
import json
import requests
import os
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


warnings.filterwarnings("ignore", category=RequestsDependencyWarning)

# Basic logger configuration

log_path = 'logs/sdk_logs.log'

log_dir = os.path.dirname(log_path)

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    level=logging.NOTSET,  # Minimum severity level to log
    # Log message format
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),  # Logs to a file
        logging.StreamHandler()  # Also outputs to the console
    ]
)



class service_discoverer:
    class ServiceDiscovererException(Exception):
        pass

    def __init__(
            self,
            config_file
    ):
        # Load configuration from file if necessary
        config_file = os.path.abspath(config_file)
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

        # Configuration path to store files
        self.config_path = os.path.dirname(os.path.abspath(config_file)) + "/"

        # Retrieve host and port information from environment variables or config
        capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
        capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
        
        # Get the folder for storing invoker certificates from environment or config
        invoker_config = config.get('invoker', {})
        invoker_general_folder = os.path.abspath(
            os.getenv('invoker_folder', invoker_config.get('invoker_folder', '')).strip()
        )
        supported_features = os.getenv('INVOKER_FOLDER', invoker_config.get('supported_features', '')).strip()
        check_authentication_data = invoker_config.get('check_authentication_data', {})
        self.check_authentication_data = {
            "ip": os.getenv('INVOKER_CHECK_AUTHENTICATION_DATA_IP', check_authentication_data.get('ip', '')).strip(),
            "port":  os.getenv('INVOKER_CHECK_AUTHENTICATION_DATA_PORT', check_authentication_data.get('port', '')).strip()
        } 
        # Retrieve CAPIF invoker username
        capif_invoker_username = os.getenv('CAPIF_USERNAME', config.get('capif_username', '')).strip()

        # Extract discover filter configuration from JSON or environment variables
        discover_filter_config = invoker_config.get('discover_filter', {})
        self.discover_filter = {
            "api-name": os.getenv('DISCOVER_FILTER_API_NAME', discover_filter_config.get('api-name', '')).strip(),
            "api-version": os.getenv('DISCOVER_FILTER_API_VERSION', discover_filter_config.get('api-version', '')).strip(),
            "comm-type": os.getenv('DISCOVER_FILTER_COMM_TYPE', discover_filter_config.get('comm-type', '')).strip(),
            "protocol": os.getenv('DISCOVER_FILTER_PROTOCOL', discover_filter_config.get('protocol', '')).strip(),
            "aef-id": os.getenv('DISCOVER_FILTER_AEF_ID', discover_filter_config.get('aef-id', '')).strip(),
            "data-format": os.getenv('DISCOVER_FILTER_DATA_FORMAT', discover_filter_config.get('data-format', '')).strip(),
            "api-cat": os.getenv('DISCOVER_FILTER_API_CAT', discover_filter_config.get('api-cat', '')).strip(),
            "preferred-aef-loc": os.getenv('DISCOVER_FILTER_PREFERRED_AEF_LOC', discover_filter_config.get('preferred-aef-loc', '')).strip(),
            "req-api-prov-name": os.getenv('DISCOVER_FILTER_REQ_API_PROV_NAME', discover_filter_config.get('req-api-prov-name', '')).strip(),
            "supported-features": os.getenv('DISCOVER_FILTER_SUPPORTED_FEATURES', discover_filter_config.get('supported-features', '')).strip(),
            "api-supported-features": os.getenv('DISCOVER_FILTER_API_SUPPORTED_FEATURES', discover_filter_config.get('api-supported-features', '')).strip(),
            "ue-ip-addr": os.getenv('DISCOVER_FILTER_UE_IP_ADDR', discover_filter_config.get('ue-ip-addr', '')).strip(),
            "service-kpis": os.getenv('DISCOVER_FILTER_SERVICE_KPIS', discover_filter_config.get('service-kpis', '')).strip()
        }

        # Store important attributes for CAPIF invocation
        self.capif_invoker_username = capif_invoker_username
        self.capif_host = capif_host
        self.capif_https_port = capif_https_port
        self.token = ""
        self.supported_features = supported_features

        # Create invoker folder dynamically based on username and folder path
        self.invoker_folder = os.path.join(invoker_general_folder, capif_invoker_username)
        os.makedirs(self.invoker_folder, exist_ok=True)

        # Load CAPIF API details

        self.invoker_capif_details = self.__load_provider_api_details()
        try:
            self.token = self.invoker_capif_details["access_token"]

        except :
            pass

        # Define paths for certificates, private keys, and CA root
        self.signed_key_crt_path = os.path.join(self.invoker_folder, self.invoker_capif_details["user_name"] + ".crt")
        self.private_key_path = os.path.join(self.invoker_folder, "private.key")
        self.ca_root_path = os.path.join(self.invoker_folder, "ca.crt")

        # Log initialization success message
        self.logger.info("ServiceDiscoverer initialized correctly")

    def get_api_provider_id(self):
        return self.invoker_capif_details["api_provider_id"]

    def __load_config_file(self, config_file: str):
        """Carga el archivo de configuración."""
        try:
            with open(config_file, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            self.logger.warning(
                f"Configuration file {config_file} not found. Using defaults or environment variables.")
            return {}

    def __load_provider_api_details(self):
        try:
            path = os.path.join(
                self.invoker_folder, "capif_api_security_context_details-"+self.capif_invoker_username+".json")
            with open(
                    path,
                    "r",
            ) as openfile:
                details = json.load(openfile)
            self.logger.info("Api provider details correctly loaded")
            return details
        except Exception as e:
            self.logger.error(
                "Error while loading Api invoker details: %s", str(e))
            raise

    def _add_trailing_slash_to_url_if_missing(self, url):
        if not url.endswith("/"):
            url += "/"
        return url

    def get_security_context(self):
        self.logger.info("Getting security context for all API's filtered")

        self.logger.info("Trying to update security context")
        self.__update_security_service()
        self.__cache_security_context()

    def get_access_token(self):
        """
        :param api_name: El nombre del API devuelto por descubrir servicios
        :param api_id: El id del API devuelto por descubrir servicios
        :param aef_id: El aef_id relevante devuelto por descubrir servicios
        :return: El token de acceso (jwt)
        """
        token_dic = self.__get_security_token()
        self.logger.info("Access token successfully obtained")
        return token_dic["access_token"]

    def __cache_security_context(self):
        try:
            path = os.path.join(
                self.invoker_folder, "capif_api_security_context_details-"+self.capif_invoker_username+".json")
            with open(
                    path, "w"
            ) as outfile:
                json.dump(self.invoker_capif_details, outfile)
            self.logger.info("Security context saved correctly")
        except Exception as e:
            self.logger.error(
                "Error when saving the security context: %s", str(e))
            raise

    def __update_security_service(self):
        """
        Actualiza el servicio de seguridad.

        :param api_id: El id del API devuelto por descubrir servicios.
        :param aef_id: El aef_id devuelto por descubrir servicios.
        :return: None.
        """
        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/trustedInvokers/{self.invoker_capif_details['api_invoker_id']}/update"
        payload = {
            "securityInfo": [],
            "notificationDestination": "https://mynotificationdest.com",
            "requestTestNotification": True,
            "websockNotifConfig": {
                "websocketUri": "string",
                "requestWebsocketUri": True
            },
            "supportedFeatures": "fff"
        }

        number_of_apis = len(
            self.invoker_capif_details["registered_security_contexes"])
        
        for i in range(0, number_of_apis):
            # Obtaining the values of api_id and aef_id for each API
            aef_profiles = self.invoker_capif_details["registered_security_contexes"][i]['aef_profiles']
            api_id = self.invoker_capif_details["registered_security_contexes"][i]['api_id']
            for n in range(0, len(aef_profiles)):
                aef_id = self.invoker_capif_details["registered_security_contexes"][i]['aef_profiles'][n]['aef_id']
                
                security_info = {
                    "prefSecurityMethods": ["Oauth"],
                    "authenticationInfo": "string",
                    "authorizationInfo": "string",
                    "aefId": aef_id,
                    "apiId": api_id
                }
                payload["securityInfo"].append(security_info)

        try:
            response = requests.post(url,
                                     json=payload,
                                     cert=(self.signed_key_crt_path,
                                           self.private_key_path),
                                     verify=self.ca_root_path)
            response.raise_for_status()
            self.logger.info("Security context correctly updated")

        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 404:
                self.logger.warning(
                    "Received 404 exception from target CAPIF. This means it is the first time this CAPIF user is getting the JWT token, redirecting to register security service in CAPIF. The process continues correctly.")
                self.__register_security_service()
            else:
                self.logger.error("HTTP error occurred: %s", str(http_err))
                raise

        except requests.RequestException as e:
            self.logger.error(
                "Error trying to update Security context: %s", str(e))
            raise

    def __register_security_service(self):
        """
        :param api_id: El id del API devuelto por descubrir servicios
        :param aef_id: El aef_id devuelto por descubrir servicios
        :return: None
        """

        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/trustedInvokers/{self.invoker_capif_details['api_invoker_id']}"
        payload = {
            "securityInfo": [],
            "notificationDestination": "https://mynotificationdest.com",
            "requestTestNotification": True,
            "websockNotifConfig": {
                "websocketUri": "string",
                "requestWebsocketUri": True
            },
            "supportedFeatures": "fff"
        }

        number_of_apis = len(
            self.invoker_capif_details["registered_security_contexes"])

        for i in range(0, number_of_apis):
            # Obtaining the values of api_id and aef_id for each API
            aef_profiles = self.invoker_capif_details["registered_security_contexes"][i]['aef_profiles']
            api_id = self.invoker_capif_details["registered_security_contexes"][i]['api_id']
            for n in range(0, len(aef_profiles)):
                aef_id = self.invoker_capif_details["registered_security_contexes"][i]['aef_profiles'][n]['aef_id']
                
                security_info = {
                    "prefSecurityMethods": ["Oauth"],
                    "authenticationInfo": "string",
                    "authorizationInfo": "string",
                    "aefId": aef_id,
                    "apiId": api_id
                }
                payload["securityInfo"].append(security_info)

            payload["securityInfo"].append(security_info)

        try:
            response = requests.put(url,
                                    json=payload,
                                    cert=(self.signed_key_crt_path,
                                          self.private_key_path),
                                    verify=self.ca_root_path
                                    )
            response.raise_for_status()
            self.logger.info("Security service properly registered")
        except requests.RequestException as e:
            self.logger.error(
                "Error when registering the security service: %s", str(e))
            raise

    def __get_security_token(self):
        """
        :param api_name: El nombre del API devuelto por descubrir servicios
        :param aef_id: El aef_id relevante devuelto por descubrir servicios
        :return: El token de acceso (jwt)
        """
        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/securities/{self.invoker_capif_details['api_invoker_id']}/token"
        # Build the scope by concatenating aef_id and api_name separated by a ';'
        scope_parts = []

        # Iterate over the registered contexts and build the scope parts
        for context in self.invoker_capif_details["registered_security_contexes"]:
            api_name = context["api_name"]
            for i in range(0, len(context['aef_profiles'])):
                aef_id = context['aef_profiles'][i]['aef_id']
                scope_parts.append(f"{aef_id}:{api_name}")

        # Join all the scope parts with ';' and add the prefix '3gpp#'
        scope = "3gpp#" + ";".join(scope_parts)

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.invoker_capif_details["api_invoker_id"],
            "client_secret": "string",
            "scope": scope
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        try:
            response = requests.post(url,
                                     headers=headers,
                                     data=payload,
                                     cert=(self.signed_key_crt_path,
                                           self.private_key_path),
                                     verify=self.ca_root_path
                                     )
            response.raise_for_status()
            response_payload = response.json()
            self.logger.info("Security token successfully obtained")
            return response_payload
        except requests.RequestException as e:
            self.logger.error(
                "Error obtaining the security token: %s ", str(e))
            raise

    def discover_service_apis(self):
        """
        Descubre los APIs de servicio desde CAPIF con filtros basados en un archivo JSON.
        :return: Payload JSON con los detalles de los APIs de servicio
        """
        # Load the parameters from the JSON file

        # Filter out parameters that are not empty
        filters = self.discover_filter

        query_params = {k: v for k, v in filters.items() if v.strip()}

        # Form the URL with the query parameters
        query_string = "&".join([f"{k}={v}" for k, v in query_params.items()])

        url = f"https://{self.capif_host}:{self.capif_https_port}/{self.invoker_capif_details['discover_services_url']}{self.invoker_capif_details['api_invoker_id']}"

        if query_string:
            url += f"&{query_string}"

        try:
            response = requests.get(
                url,
                headers={"Content-Type": "application/json"},
                cert=(self.signed_key_crt_path, self.private_key_path),
                verify=self.ca_root_path
            )

            response.raise_for_status()
            response_payload = response.json()
            self.logger.info("Service APIs successfully discovered")
            return response_payload
        except requests.RequestException as e:
            self.logger.error("Error discovering service APIs: %s", str(e))
            raise

    def retrieve_api_description_by_name(self, api_name):
        """
        Recupera la descripción del API por nombre.
        :param api_name: Nombre del API
        :return: Descripción del API
        """
        self.logger.info(
            "Retrieving the API description for api_name=%s", api_name)
        capif_apifs = self.discover_service_apis()
        endpoints = [api for api in capif_apifs["serviceAPIDescriptions"]
                     if api["apiName"] == api_name]
        if not endpoints:
            error_message = (
                f"Could not find available endpoints for api_name: {api_name}. "
                "Make sure that a) your Invoker is registered and onboarded to CAPIF and "
                "b) the NEF emulator has been registered and onboarded to CAPIF"
            )
            self.logger.error(error_message)
            raise ServiceDiscoverer.ServiceDiscovererException(error_message)
        else:
            self.logger.info("API description successfully retrieved")
            return endpoints[0]

    def retrieve_specific_resource_name(self, api_name, resource_name):
        """
        Recupera la URL para recursos específicos dentro de los APIs.
        :param api_name: Nombre del API
        :param resource_name: Nombre del recurso
        :return: URL del recurso específico
        """
        self.logger.info(
            "Retrieving the URL for resource_name=%s in api_name=%s", resource_name, api_name)
        api_description = self.retrieve_api_description_by_name(api_name)
        version_dictionary = api_description["aefProfiles"][0]["versions"][0]
        version = version_dictionary["apiVersion"]
        resources = version_dictionary["resources"]
        uris = [resource["uri"]
                for resource in resources if resource["resourceName"] == resource_name]

        if not uris:
            error_message = f"Could not find resource_name: {resource_name} at api_name {api_name}"
            self.logger.error(error_message)
            raise ServiceDiscoverer.ServiceDiscovererException(error_message)
        else:
            uri = uris[0]
            if not uri.startswith("/"):
                uri = "/" + uri
            if api_name.endswith("/"):
                api_name = api_name[:-1]
            result_url = api_name + "/" + version + uri
            self.logger.info(
                "URL of the specific resource successfully retrieved: %s", result_url)
            return result_url

    def save_security_token(self, token):
        self.invoker_capif_details["access_token"] = token
        self.__cache_security_context()

    def get_tokens(self):

        self.get_security_context()
        token = self.get_access_token()
        self.token = token
        self.save_security_token(token)

    def discover(self):
        endpoints = self.discover_service_apis()

        if len(endpoints) > 0:
            self.save_api_discovered(endpoints)
        else:
            self.logger.error(
                "No endpoints have been registered. Make sure a Provider has Published an API to CAPIF first")

    def save_api_discovered(self, endpoints):
        self.invoker_capif_details["registered_security_contexes"] = []
        p = 0
        for service in endpoints["serviceAPIDescriptions"]:
            api_id = service["apiId"]
            api_name = service["apiName"]
            aef_profiles = []
            self.invoker_capif_details["registered_security_contexes"].append({"api_name": api_name, "api_id": api_id, "aef_profiles": aef_profiles})
            for n in service["aefProfiles"]:
                versions = n["versions"]
                aef_id = n["aefId"]
                for m in n["interfaceDescriptions"]:
                    ip = m["ipv4Addr"]
                    port = m["port"]
                    self.invoker_capif_details["registered_security_contexes"][p]['aef_profiles'].append(
                        {"aef_id": aef_id, "ip": ip, "port": port, "versions": versions})
            p += 1

        self.save_api_details()

    def save_api_details(self):
        try:
            # Define the path to save the details
            file_path = os.path.join(
                self.invoker_folder, "capif_api_security_context_details-" + self.capif_invoker_username + ".json")

            # Save the details as a JSON file
            with open(file_path, "w") as outfile:
                json.dump(self.invoker_capif_details, outfile, indent=4)

            # Log the success of the operation
            self.logger.info("API provider details correctly saved")

        except Exception as e:
            # Log any errors that occur during the save process
            self.logger.error(
                "Error while saving API provider details: %s", str(e))
            raise

    def check_authentication(self):
        print("hola")
        self.logger.info("Checking authentication")
        try:
            invoker_details = self.__load_provider_api_details()
            invoker_id = invoker_details["api_invoker_id"]
            check_auth = self.check_authentication_data
            url = "http://"+f"{check_auth['ip']}:{check_auth['port']}/" + "aef-security/v1/check-authentication"
            
            payload = {
                "apiInvokerId": f"{invoker_id}",
                "supportedFeatures": f"{self.supported_features}"
            }
            print(self.supported_features)
            
            headers = {
                "Authorization": "Bearer {}".format(self.token),
                "Content-Type": "application/json",
            }
            
            response = requests.request(
                "POST",
                url,
                headers=headers,
                json=payload 
            )
            
            print(response.text)
            response.raise_for_status()
            self.logger.info("Authentication of supported_features checked")
            
        except Exception as e:
            self.logger.error(
                f"Error during checking Invoker supported_features : {e} - Response: {response.text}")
            raise
