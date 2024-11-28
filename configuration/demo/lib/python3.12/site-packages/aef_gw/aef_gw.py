import json
import logging
import os
import shutil
import yaml
import opencapif_sdk
import subprocess
from collections import defaultdict

log_path = 'logs/aef_gw_logs.log'

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


class aef_gw:

    def __init__(self, northbound_path, southbound_path, debug):
        self.northbound_path = os.path.abspath(northbound_path)
        self.southbound_path = os.path.abspath(southbound_path)
        self.logger = logging.getLogger(self.__class__.__name__)
        # Initialize logger for this class
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.WARNING)
        self.northbound_info = self.__load_api_file(self.northbound_path)
        self.southbound_info = self.__load_api_file(self.southbound_path)
        # First is going to check the correct format of the northbound file
        self.__check_northbound()
        self.__check_southbound()
        
    def start(self):
        self.opencapif_sdk_configuration = self.northbound_info["northbound"]["opencapif_sdk_configuration"]
        self.openapi_info = self.northbound_info["northbound"]["openapi"]
        self.opencapif_sdk_configuration["provider"]["provider_folder"] = "./aef_gw/provider_information"
        self.opencapif_sdk_configuration["provider"]["aefs"] = "1"
        self.opencapif_sdk_configuration["provider"]["apfs"] = "1"
        self.__openapi_modifications()
        os.makedirs("aef_gw", exist_ok=True)
        self.__save_openapi_info()
        self.__save_opencapif_sdk_configuration()

        self.__opencapif_connection()

        self.__check_south_and_north_match()

        if self.southbound_info["southbound"]["authentication_method"] == "HTTP Basic Authentication":
            self.__generate_northbound_api()
        if self.southbound_info["southbound"]["authentication_method"] == "JWT Bearer Token":
            self.__generate_northbound_api_jwt()

    def run(self):
        """Start the API in the background."""
        self.logger.info("Preparing to start the API...")
        try:
            command = ["python3", "./aef_gw/run.py"]
            self.logger.info("Starting the FastAPI server for the API")
            subprocess.run(command)
            self.logger.info("API started successfully.")
        except Exception as e:
            self.logger.error(f"Failed to start API: {e}")

    def remove(self):
        """Remove the aef_gw and logs folders."""
        self.logger.info("Initiating removal process...")
        # Disconnect from OpenCAPIF
        self.__opencapif_disconnect()

        aef_gw_path = './aef_gw'
        logs_path = './logs'

        # Remove aef_gw folder
        try:
            if os.path.exists(aef_gw_path):
                shutil.rmtree(aef_gw_path)
                self.logger.info(f"Removed folder: {aef_gw_path}")
            else:
                self.logger.warning(f"Folder not found: {aef_gw_path}")
        except Exception as e:
            self.logger.error(f"Failed to remove folder {aef_gw_path}: {e}")

        # Remove logs folder
        try:
            if os.path.exists(logs_path):
                shutil.rmtree(logs_path)
                self.logger.info(f"Removed folder: {logs_path}")
            else:
                self.logger.warning(f"Folder not found: {logs_path}")
        except Exception as e:
            self.logger.error(f"Failed to remove folder {logs_path}: {e}")

        self.logger.info("Removal process completed.")

    def refresh(self):
        file_path = "./aef_gw/run.py"

        old_token_pattern = r'headers\["Authorization"\]\s*=\s*f?"Bearer\s+.*?"'

        token = self.southbound_info["southbound"]["credentials"].get("jwt")

        new_token = f'headers["Authorization"] = f"Bearer {token}"'

        try:

            with open(file_path, "r") as file:
                content = file.read()

            import re
            updated_content = re.sub(old_token_pattern, new_token, content)

            with open(file_path, "w") as file:
                file.write(updated_content)

            self.logger.info("Token has been refreshed successfully")
            
            self.run()
        except FileNotFoundError:
            raise FileNotFoundError(f"The File {file_path} doesnt exists.")
        except Exception as e:
            raise RuntimeError(f"Error while updating the file: {e}")


    def __opencapif_disconnect(self):
        provider = opencapif_sdk.capif_provider_connector(config_file="./aef_gw/opencapif_sdk_configuration.json")
        provider.offboard_provider()

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

    def __check_northbound(self):
        """Verifies that the structure of the northbound YAML file matches the expected format."""
        expected_structure = {
            'northbound': {
                'ip': str,
                'port': int,
                'opencapif_sdk_configuration': {
                    'capif_host': str,
                    'register_host': str,
                    'capif_https_port': str,
                    'capif_register_port': str,
                    'capif_username': str,
                    'capif_password': str,
                    'debug_mode': str,
                    'provider': {
                        'cert_generation': {
                            'csr_common_name': str,
                            'csr_organizational_unit': str,
                            'csr_organization': str,
                            'csr_locality': str,
                            'csr_state_or_province_name': str,
                            'csr_country_name': str,
                            'csr_email_address': str
                        }
                    }
                },
                'openapi': {
                    'openapi': str,
                    'info': dict,
                    'security': list,
                    'components': dict,
                    'paths': dict
                }
            }
        }

        def validate_structure(data, expected):
            if isinstance(expected, dict):
                if not isinstance(data, dict):
                    return False
                for key, sub_structure in expected.items():
                    if key not in data:
                        self.logger.error(f"Missing key: '{key}'")
                        return False
                    if not validate_structure(data[key], sub_structure):
                        return False
            return True

        if validate_structure(self.northbound_info, expected_structure):
            self.logger.info("The structure of the northbound file is valid.")
        else:
            self.logger.error("The structure of the northbound file does not match the expected format.")

    def __save_openapi_info(self, output_path="./aef_gw/openapi_info.yaml"):
        """Saves the openapi_info content to a YAML file with proper indentation and formatting."""
        try:
            with open(output_path, 'w') as yaml_file:
                yaml.dump(
                    self.openapi_info,
                    yaml_file,
                    default_flow_style=False,
                    sort_keys=False,  # Preserves the order in the dictionary
                    allow_unicode=True,  # Supports unicode characters in the output
                    indent=4  # Ensures consistent indentation for readability
                )
            self.logger.info(f"OpenAPI info saved successfully to {output_path}")
        except yaml.YAMLError as yaml_error:
            self.logger.error(f"YAML formatting error while saving OpenAPI info: {yaml_error}")
        except IOError as io_error:
            self.logger.error(f"I/O error while saving OpenAPI info to {output_path}: {io_error}")
        except Exception as e:
            self.logger.error(f"Unexpected error while saving OpenAPI info to YAML: {e}")

    def __save_opencapif_sdk_configuration(self, output_path="./aef_gw/opencapif_sdk_configuration.json"):
        """Saves the opencapif_sdk_configuration content to a JSON file."""
        try:
            with open(output_path, 'w') as json_file:
                json.dump(self.opencapif_sdk_configuration, json_file, indent=4)
            self.logger.info(f"OpenCAPIF SDK configuration saved successfully to {output_path}")
        except Exception as e:
            self.logger.error(f"Error saving OpenCAPIF SDK configuration to JSON: {e}")

    def __opencapif_connection(self):
        provider = opencapif_sdk.capif_provider_connector(config_file="./aef_gw/opencapif_sdk_configuration.json")
        provider.onboard_provider()
        translator = opencapif_sdk.api_schema_translator("./aef_gw/openapi_info.yaml")
        translator.build("capif_publish_description", f"{self.northbound_info["northbound"]["ip"]}", self.northbound_info["northbound"]["port"])
        os.replace("./capif_publish_description.json", "./aef_gw/capif_publish_description.json")
        provider.api_description_path = "./aef_gw/capif_publish_description.json"

        apf = provider.provider_capif_ids["APF-1"]

        aef = provider.provider_capif_ids["AEF-1"]

        provider.publish_req['publisher_apf_id'] = apf
        provider.publish_req['publisher_aefs_ids'] = [aef]
        provider.publish_services()

    def __generate_northbound_api(self):

        api_file_path = "./aef_gw/run.py"

        southbound_paths = defaultdict(list)

        for path in self.southbound_info["southbound"]["paths"]:
            southbound_paths[path["northbound_path"]].append({
                "southbound_path": path["southbound_path"],
                "method": path["method"]
            })

        southbound_paths = dict(southbound_paths)

        api_code = f"""
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, HTTPException, Security, Path , Request
from fastapi.security import HTTPBearer
from jose import jwt
from pydantic import BaseModel, create_model
from OpenSSL import crypto
import uvicorn
import json
import requests
import subprocess

class NorthboundAPI:
    def __init__(self, stored_routes, methods, parameters, responses, request_bodies, summaries, descriptions, tags, operation_ids, dynamic_models):
        self.stored_routes = stored_routes
        self.methods = methods
        self.parameters = parameters
        self.responses = responses
        self.request_bodies = request_bodies
        self.summaries = summaries
        self.descriptions = descriptions
        self.tags = tags
        self.operation_ids = operation_ids
        self.dynamic_models = dynamic_models
        self.PUBLIC_KEY = self.config_jwt()

    def config_jwt(self):
        try:
            with open(f"./aef_gw/provider_information/{self.opencapif_sdk_configuration['capif_username']}/capif_cert_server.pem", "rb") as cert_file:
                cert = cert_file.read()

            crt_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            pub_key_object = crt_obj.get_pubkey()
            pub_key_string = crypto.dump_publickey(crypto.FILETYPE_PEM, pub_key_object).decode("utf-8")
            return pub_key_string
        except Exception as e:
            print("Error in JWT configuration:", e)
            raise

    def decode_token(self, token: str = Security(HTTPBearer())):
        try:
            decoded = jwt.decode(token.credentials, self.PUBLIC_KEY, algorithms=["RS256"])
            return decoded
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

    def create_route_handler(self, route, params, decode_token, method):

        southbound_paths = {southbound_paths}

        params_dict={self.parameters_dict}

        possible_mappings = southbound_paths.get(route, [])
        southbound_mapping = next(
            (mapping for mapping in possible_mappings if mapping["method"].lower() == method.lower()),
            None
        )

        if not southbound_mapping:
            raise ValueError(f"No southbound path defined for route {{route}} with method {{method}}")

        southbound_url_template = southbound_mapping["southbound_path"]

        async def route_handler(
            request: Request,
            token=Depends(decode_token)
        ):
            try:
                path_params = request.path_params

                mapped_path_params = {{params_dict.get(key, key): value for key, value in path_params.items()}}

                payload = await request.json() if method.upper() in ["POST", "PUT", "PATCH"] else None
                try:
                    southbound_url = southbound_url_template.format(**mapped_path_params)
                except KeyError as e:
                    raise HTTPException(status_code=400, detail=f"Missing path parameter: {{e}}")

                headers = {{key: value for key, value in request.headers.items() if key.lower() != "host"}}

                print(f"Forwarding {{method.upper()}} request to {{southbound_url}} with payload: {{payload}}")

                response = requests.request(
                    method=method.upper(),
                    url=f"http://{self.southbound_info["southbound"]["ip"]}:{self.southbound_info["southbound"]["port"]}{{southbound_url}}",
                    auth=(
                        "{self.southbound_info["southbound"]["credentials"]["username"]}",
                        "{self.southbound_info["southbound"]["credentials"]["password"]}"
                    ),
                    headers=headers,
                    json=payload,
                    timeout=10
                )
                response.raise_for_status()

                return response.json()

            except requests.exceptions.Timeout:
                raise HTTPException(status_code=504, detail="Southbound server timeout")
            except requests.exceptions.ConnectionError:
                raise HTTPException(status_code=502, detail="Southbound server not reachable")
            except requests.RequestException as e:
                raise HTTPException(status_code=502, detail=f"Error forwarding request: {{str(e)}}")

        return route_handler

    def generate_northbound_api(self, app: FastAPI):
        for n in range(len(self.stored_routes)):
            method = self.methods[n].lower()
            route = self.stored_routes[n]
            params = self.parameters[n]
            response_model = None
            if "200" in self.responses[n]:
                schema_ref = self.responses[n]["200"].get("content", {{}}).get("application/json", {{}}).get("schema", {{}}).get("$ref")
                if schema_ref:
                    model_name = schema_ref.split("/")[-1]
                    response_model = self.dynamic_models.get(model_name)

            summary = self.summaries[n]
            description = self.descriptions[n]
            tags = self.tags[n]
            operation_id = self.operation_ids[n]

            route_handler = self.create_route_handler(route, params, self.decode_token, method)

            app.add_api_route(
                path=route,
                endpoint=route_handler,
                methods=[method.upper()],
                response_model=response_model,
                summary=summary,
                description=description,
                tags=tags,
                operation_id=operation_id,
                responses=self.responses[n],
            )

def create_pydantic_model(name: str, schema: Dict[str, Any]) -> BaseModel:
    fields = {{}}
    required_fields = schema.get("required", [])

    type_mapping = {{
        "string": str,
        "integer": int,
        "boolean": bool,
        "array": list,
        "number": float,
    }}

    for field_name, field_schema in schema.get("properties", {{}}).items():
        field_type = field_schema.get("type", "string")

        if field_type == "array":
            items_type = field_schema.get("items", {{}}).get("type", "string")
            python_type = List[type_mapping.get(items_type, Any)]
        else:
            python_type = type_mapping.get(field_type, Any)

        field = (python_type, ...) if field_name in required_fields else (python_type, None)
        fields[field_name] = field

    return create_model(name, **fields)

def register_dynamic_models(app: FastAPI, dynamic_models: Dict[str, BaseModel]):
    app.openapi_schema = {self.openapi_info}
    app.openapi_schema["components"]["schemas"] = {{
        model_name : model.model_json_schema(ref_template=f"#/components/schemas/{{model_name}}")
        for model_name, model in dynamic_models.items()
    }}
if __name__ == "__main__":
    app = FastAPI()

    components = {self.components}

    dynamic_models = {{
        model_name: create_pydantic_model(model_name, model_schema)
        for model_name, model_schema in components.items()
    }}

    register_dynamic_models(app, dynamic_models)
    stored_routes = {self.stored_routes}
    methods = {self.methods}
    parameters = {self.parameters}
    responses = {self.responses}
    request_bodies = {self.request_bodies}
    summaries = {self.summaries}
    descriptions = {self.descriptions}
    tags = {self.tags}
    operation_ids = {self.operation_ids}

    api = NorthboundAPI(stored_routes, methods, parameters, responses, request_bodies, summaries, descriptions, tags, operation_ids, dynamic_models)
    api.generate_northbound_api(app)
    uvicorn.run(app, host="{self.northbound_info["northbound"]["ip"]}", port={self.northbound_info["northbound"]["port"]})
"""

        with open(api_file_path, 'w') as file:
            file.write(api_code)
        self.logger.info(f"API generated and saved in {api_file_path}")

        command = ["python3", "./aef_gw/run.py"]
        self.logger.info("Starting the FastAPI server for the API")

        subprocess.run(command)

    def __check_southbound(self):
        """Verifies that the structure of the southbound YAML file matches the expected format."""
        expected_structure = {
            'southbound': {
                'ip': str,
                'port': int,
                'type': str,
                'authentication_method': str,
                'credentials': dict,  # Validate structure based on authentication_method
                'paths': [
                    {
                        'northbound_path': str,
                        'southbound_path': str,
                        'method': str,
                        'parameters': list  # Optional key
                    }
                ]
            }
        }

        def validate_structure(data, expected):
            """Recursive helper function to validate the structure."""
            if isinstance(expected, dict):
                if not isinstance(data, dict):
                    self.logger.error(f"Expected a dict but got {type(data).__name__}. Data: {data}")
                    return False
                for key, sub_structure in expected.items():
                    if key not in data:
                        # Skip optional keys like 'parameters'
                        if key == "parameters":
                            continue
                        self.logger.error(f"Missing key: {key}")
                        return False
                    if key == "credentials":
                        # Validate credentials based on authentication_method
                        if not validate_credentials(data, data.get('authentication_method')):
                            return False
                    elif not validate_structure(data[key], sub_structure):
                        self.logger.error(f"Key '{key}' does not match the expected structure. Data: {data.get(key)}")
                        return False
            elif isinstance(expected, list):
                if not isinstance(data, list):
                    self.logger.error(f"Expected a list but got {type(data).__name__}. Data: {data}")
                    return False
                for item in data:
                    if not validate_structure(item, expected[0]):
                        self.logger.error(f"An item in the list does not match the expected structure. Item: {item}")
                        return False
            elif isinstance(expected, type):
                if not isinstance(data, expected):
                    self.logger.error(f"Expected {expected.__name__} but got {type(data).__name__}. Value: {data}")
                    return False
            else:
                self.logger.error(f"Unexpected structure type. Expected: {expected}, got: {data}")
                return False

            return True

        def validate_credentials(data, authentication_method):
            """Validate the structure of the credentials field based on authentication_method."""
            credentials = data.get('credentials', {})
            if authentication_method == "HTTP Basic Authentication":
                if not isinstance(credentials, dict) or 'username' not in credentials or 'password' not in credentials:
                    self.logger.error("For HTTP Basic Authentication, 'credentials' must contain 'username' and 'password'.")
                    return False
            elif authentication_method == "JWT Bearer Token":
                if not isinstance(credentials, dict) or 'jwt' not in credentials:
                    self.logger.error("For JWT Bearer Token, 'credentials' must contain 'jwt'.")
                    return False
            else:
                self.logger.error(f"Unsupported authentication method: {authentication_method}")
                return False
            return True

        # Validate the southbound_info against the expected structure
        if validate_structure(self.southbound_info, expected_structure):
            self.logger.info("The structure of the southbound file is valid.")
        else:
            self.logger.error("The structure of the southbound file does not match the expected format.")

    def __openapi_modifications(self):
        self.logger.info("Starting OpenAPI modifications.")
        openapi_structure = self.openapi_info
        self.stored_routes = []
        self.methods = []
        self.parameters = []
        self.responses = []
        self.request_bodies = []
        self.summaries = []
        self.descriptions = []
        self.tags = []
        self.operation_ids = []
        self.components = {}

        if 'components' not in openapi_structure:
            openapi_structure['components'] = {}
            self.logger.debug("Added 'components' to OpenAPI structure.")
        openapi_structure['components']['securitySchemes'] = {}
        openapi_structure['components']['securitySchemes']['jwt'] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
        self.logger.debug("Added JWT security scheme to OpenAPI structure.")

        openapi_structure['security'] = [{"jwt": []}]
        self.logger.debug("Set global security configuration for JWT.")

        if 'components' in openapi_structure:
            self.components = {
                key: value for key, value in openapi_structure['components'].get('schemas', {}).items() if key != 'securitySchemes'
            }
            self.logger.info(f"Extracted {len(self.components)} components from OpenAPI structure.")

        for path, methods in openapi_structure.get('paths', {}).items():
            self.logger.debug(f"Processing path: {path}")
            path_parts = [part for part in path.strip('/').split('/') if part]
            params = [part.strip('{}') for part in path_parts if part.startswith('{')]

            for method, details in methods.items():
                self.logger.debug(f"Processing method '{method}' for path '{path}'.")

                if 'security' in details:
                    del details['security']
                    self.logger.debug(f"Removed 'security' field from method '{method}' in path '{path}'.")

                self.stored_routes.append(path)
                self.methods.append(method)
                self.parameters.append(details.get('parameters', params))
                self.responses.append(details.get('responses', None))
                self.request_bodies.append(details.get('requestBody', None))
                self.summaries.append(details.get('summary', None))
                self.descriptions.append(details.get('description', None))
                self.tags.append(details.get('tags', []))
                self.operation_ids.append(details.get('operationId', None))

        self.logger.info("Finished OpenAPI modifications.")

    def __check_south_and_north_match(self):
        self.logger.info("Starting validation of northbound and southbound path matching.")

        # Extract northbound paths
        northbound_paths = self.northbound_info["northbound"]["openapi"].get("paths", {})
        self.logger.debug("Northbound paths extracted")

        # Build southbound path dictionary
        southbound_paths = defaultdict(list)
        for path in self.southbound_info["southbound"]["paths"]:
            southbound_paths[path["northbound_path"]].append({
                "southbound_path": path["southbound_path"],
                "method": path["method"]
            })
        southbound_dict = dict(southbound_paths)
        self.logger.debug("Southbound paths dictionary constructed ")

        # Validate paths and methods
        for path, methods in northbound_paths.items():
            if path not in southbound_dict:
                self.logger.error(f"Northbound path '{path}' does not have a corresponding southbound entry.")
                return False

            for method, details in methods.items():
                if method not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    self.logger.error(f"Unsupported HTTP method '{method}' found for the path '{path}'.")
                    return False

                method_match = any(item["method"].lower() == method.lower() for item in southbound_dict[path])
                if not method_match:
                    self.logger.error(f"HTTP method '{method.upper()}' for the northbound path '{path}' does not have a corresponding southbound entry.")
                    return False

        self.logger.info("Northbound paths and methods successfully validated against southbound.")

        # Extract and log parameter mappings
        parameters_dict = {}
        for path_entry in self.southbound_info["southbound"]["paths"]:
            parameters = path_entry.get("parameters", [])
            self.logger.debug(f"Processing parameters for southbound path: {path_entry['southbound_path']}")

            for param in parameters:
                parameters_dict.update(param)
                self.logger.debug(f"Parameter mapping updated: {param}")

        self.parameters_dict = parameters_dict
        self.logger.info("Parameter mappings successfully extracted and stored.")

    def __generate_northbound_api_jwt(self):

        api_file_path = "./aef_gw/run.py"

        southbound_paths = defaultdict(list)

        for path in self.southbound_info["southbound"]["paths"]:
            southbound_paths[path["northbound_path"]].append({
                "southbound_path": path["southbound_path"],
                "method": path["method"]
            })

        southbound_paths = dict(southbound_paths)

        api_code = f"""
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, HTTPException, Security, Path , Request
from fastapi.security import HTTPBearer
from jose import jwt
from pydantic import BaseModel, create_model
from OpenSSL import crypto
import uvicorn
import json
import requests
import subprocess

class NorthboundAPI:
    def __init__(self, stored_routes, methods, parameters, responses, request_bodies, summaries, descriptions, tags, operation_ids, dynamic_models):
        self.stored_routes = stored_routes
        self.methods = methods
        self.parameters = parameters
        self.responses = responses
        self.request_bodies = request_bodies
        self.summaries = summaries
        self.descriptions = descriptions
        self.tags = tags
        self.operation_ids = operation_ids
        self.dynamic_models = dynamic_models
        self.PUBLIC_KEY = self.config_jwt()

    def config_jwt(self):
        try:
            with open(f"./aef_gw/provider_information/{self.opencapif_sdk_configuration['capif_username']}/capif_cert_server.pem", "rb") as cert_file:
                cert = cert_file.read()

            crt_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            pub_key_object = crt_obj.get_pubkey()
            pub_key_string = crypto.dump_publickey(crypto.FILETYPE_PEM, pub_key_object).decode("utf-8")
            return pub_key_string
        except Exception as e:
            print("Error in JWT configuration:", e)
            raise

    def decode_token(self, token: str = Security(HTTPBearer())):
        try:
            decoded = jwt.decode(token.credentials, self.PUBLIC_KEY, algorithms=["RS256"])
            return decoded
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

    def create_route_handler(self, route, params, decode_token, method):
        southbound_paths = {southbound_paths}
        params_dict = {self.parameters_dict}

        possible_mappings = southbound_paths.get(route, [])
        southbound_mapping = next(
            (mapping for mapping in possible_mappings if mapping["method"].lower() == method.lower()),
            None
        )

        if not southbound_mapping:
            raise ValueError(f"No southbound path defined for route {{route}} with method {{method}}")

        southbound_url_template = southbound_mapping["southbound_path"]

        async def route_handler(
            request: Request,
            token=Depends(decode_token)
        ):
            try:
                path_params = request.path_params

                mapped_path_params = {{params_dict.get(key, key): value for key, value in path_params.items()}}

                payload = await request.json() if method.upper() in ["POST", "PUT", "PATCH"] else None
                try:
                    southbound_url = southbound_url_template.format(**mapped_path_params)
                except KeyError as e:
                    raise HTTPException(status_code=400, detail=f"Missing path parameter: {{e}}")

                headers = {{key: value for key, value in request.headers.items() if key.lower() != "host"}}

                headers["Authorization"] = "Bearer {self.southbound_info["southbound"]["credentials"].get("jwt")}"

                if not headers["Authorization"]:
                    raise HTTPException(status_code=500, detail="JWT token not configured for southbound authentication")

                print(f"Forwarding {{method.upper()}} request to {{southbound_url}} with payload: {{payload}}")

                response = requests.request(
                    method=method.upper(),
                    url=f"http://{self.southbound_info['southbound']['ip']}:{self.southbound_info['southbound']['port']}{{southbound_url}}",
                    headers=headers,
                    json=payload,
                    timeout=10
                )
                response.raise_for_status()

                return response.json()

            except requests.exceptions.Timeout:
                raise HTTPException(status_code=504, detail="Southbound server timeout")
            except requests.exceptions.ConnectionError:
                raise HTTPException(status_code=502, detail="Southbound server not reachable")
            except requests.RequestException as e:
                raise HTTPException(status_code=502, detail=f"Error forwarding request: {{str(e)}}")

        return route_handler


    def generate_northbound_api(self, app: FastAPI):
        for n in range(len(self.stored_routes)):
            method = self.methods[n].lower()
            route = self.stored_routes[n]
            params = self.parameters[n]
            response_model = None
            if "200" in self.responses[n]:
                schema_ref = self.responses[n]["200"].get("content", {{}}).get("application/json", {{}}).get("schema", {{}}).get("$ref")
                if schema_ref:
                    model_name = schema_ref.split("/")[-1]
                    response_model = self.dynamic_models.get(model_name)

            summary = self.summaries[n]
            description = self.descriptions[n]
            tags = self.tags[n]
            operation_id = self.operation_ids[n]

            route_handler = self.create_route_handler(route, params, self.decode_token, method)

            app.add_api_route(
                path=route,
                endpoint=route_handler,
                methods=[method.upper()],
                response_model=response_model,
                summary=summary,
                description=description,
                tags=tags,
                operation_id=operation_id,
                responses=self.responses[n],
            )

def create_pydantic_model(name: str, schema: Dict[str, Any]) -> BaseModel:
    fields = {{}}
    required_fields = schema.get("required", [])

    type_mapping = {{
        "string": str,
        "integer": int,
        "boolean": bool,
        "array": list,
        "number": float,
    }}

    for field_name, field_schema in schema.get("properties", {{}}).items():
        field_type = field_schema.get("type", "string")

        if field_type == "array":
            items_type = field_schema.get("items", {{}}).get("type", "string")
            python_type = List[type_mapping.get(items_type, Any)]
        else:
            python_type = type_mapping.get(field_type, Any)

        field = (python_type, ...) if field_name in required_fields else (python_type, None)
        fields[field_name] = field

    return create_model(name, **fields)

def register_dynamic_models(app: FastAPI, dynamic_models: Dict[str, BaseModel]):
    app.openapi_schema = {self.openapi_info}
    app.openapi_schema["components"]["schemas"] = {{
        model_name : model.model_json_schema(ref_template=f"#/components/schemas/{{model_name}}")
        for model_name, model in dynamic_models.items()
    }}
if __name__ == "__main__":
    app = FastAPI()

    components = {self.components}

    dynamic_models = {{
        model_name: create_pydantic_model(model_name, model_schema)
        for model_name, model_schema in components.items()
    }}

    register_dynamic_models(app, dynamic_models)
    stored_routes = {self.stored_routes}
    methods = {self.methods}
    parameters = {self.parameters}
    responses = {self.responses}
    request_bodies = {self.request_bodies}
    summaries = {self.summaries}
    descriptions = {self.descriptions}
    tags = {self.tags}
    operation_ids = {self.operation_ids}

    api = NorthboundAPI(stored_routes, methods, parameters, responses, request_bodies, summaries, descriptions, tags, operation_ids, dynamic_models)
    api.generate_northbound_api(app)
    uvicorn.run(app, host="{self.northbound_info["northbound"]["ip"]}", port={self.northbound_info["northbound"]["port"]})
"""

        with open(api_file_path, 'w') as file:
            file.write(api_code)
        self.logger.info(f"API generated and saved in {api_file_path}")

        command = ["python3", "./aef_gw/run.py"]
        self.logger.info("Starting the FastAPI server for the API")

        subprocess.run(command)
