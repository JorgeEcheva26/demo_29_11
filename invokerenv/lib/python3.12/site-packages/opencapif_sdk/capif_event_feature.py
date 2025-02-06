from opencapif_sdk import capif_invoker_connector,capif_provider_connector
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


class capif_invoker_event_feature(capif_invoker_connector):

    def create_subscription(self, name):

        invoker_capif_details = self.invoker_capif_details

        subscriberId = invoker_capif_details["api_invoker_id"]

        path = self.capif_https_url + f"capif-events/v1/{subscriberId}/subscriptions"

        payload = {
            "events": self.events_description,
            "eventFilters": self.events_filter,
            "eventReq": {},  # TO IMPROVE !!!
            "notificationDestination": f"{self.capif_callback_url}",
            "requestTestNotification": True,
            "websockNotifConfig": {
                "websocketUri": f"{self.capif_callback_url}",
                "requestWebsocketUri": True
            },
            "supportedFeatures": f"{self.supported_features}"
        }
        
        try:
            response = requests.post(
                url=path,
                json=payload,
                headers={"Content-Type": "application/json"},
                cert=(self.signed_key_crt_path, self.private_key_path),
                verify=os.path.join(self.invoker_folder, "ca.crt")
            )
            response.raise_for_status()
            location_header = response.headers.get("Location")

            if location_header:
                # Extrae el identificador de la URL en el encabezado 'Location'
                identifier = location_header.rstrip('/').split('/')[-1]
                self.logger.info(f"Subscriptionid obtained: {identifier}")
            else:
                self.logger.error("The Location header is not available in the response")

            path = os.path.join(self.invoker_folder, "capif_subscriptions_id.json")

            # Load or initialize the subscription dictionary
            # Load or initialize the subscription dictionary
            if os.path.exists(path):
                subscription = self._load_config_file(path)
                if not isinstance(subscription, dict):
                    raise TypeError(f"Expected 'subscription' to be a dict, but got {type(subscription).__name__}")
            else:
                subscription = {}

            if not isinstance(subscriberId, (str, int)):
                raise TypeError(f"Expected 'subscriberId' to be a string or integer, but got {type(subscriberId).__name__}")

            # Convert events_description to a string if it isn't already
            if not isinstance(name, str):
                name = str(name)

            if str(subscriberId) not in subscription:
                # If the subscriberId is not in the subscription, create an empty dictionary for it
                subscription[str(subscriberId)] = {}
            # Update the subscription structure
            subscription[str(subscriberId)][name] = identifier

            # Save the updated dictionary back to the file
            self._create_or_update_file("capif_subscriptions_id", "json", subscription, "w")

        except Exception as e:
            self.logger.error("Unexpected error: %s", e)
            return None, {"error": f"Unexpected error: {e}"}

    def delete_subscription(self, name):
        invoker_capif_details = self.invoker_capif_details

        subscriberId = invoker_capif_details["api_invoker_id"]

        path = os.path.join(self.invoker_folder, "capif_subscriptions_id.json")

        if os.path.exists(path):
            subscription = self._load_config_file(path)
            if not isinstance(subscription, dict):
                raise TypeError(f"Expected 'subscription' to be a dict, but got {type(subscription).__name__}")

            if subscriberId in subscription and name in subscription[subscriberId]:
                identifier = subscription[subscriberId][name]

                # Attempt to delete the subscription from CAPIF
                delete_path = self.capif_https_url + f"capif-events/v1/{subscriberId}/subscriptions/{identifier}"

                try:
                    response = requests.delete(
                        url=delete_path,
                        headers={"Content-Type": "application/json"},
                        cert=(self.signed_key_crt_path, self.private_key_path),
                        verify=os.path.join(self.invoker_folder, "ca.crt")
                    )
                    response.raise_for_status()

                    # Remove the service entry from the subscription dictionary
                    del subscription[subscriberId][name]

                    # If no more services exist for the subscriber, remove the subscriber entry
                    if not subscription[subscriberId]:
                        del subscription[subscriberId]

                    # Save the updated dictionary back to the file
                    self._create_or_update_file("capif_subscriptions_id", "json", subscription, "w")

                    self.logger.info(f"Successfully deleted subscription for service '{name}'")

                except Exception as e:
                    self.logger.error("Unexpected error: %s", e)
                    return None, {"error": f"Unexpected error: {e}"}

            else:
                self.logger.warning(f"Service '{name}' not found for subscriber '{subscriberId}'")
                return None, {"error": f"Service '{name}' not found for subscriber '{subscriberId}'"}
        else:
            self.logger.error("Subscription file not found at path: %s", path)
            return None, {"error": "Subscription file not found"}

    def update_subcription(self, name):
        invoker_capif_details = self.invoker_capif_details

        subscriberId = invoker_capif_details["api_invoker_id"]

        path = os.path.join(self.invoker_folder, "capif_subscriptions_id.json")

        payload = {
            "events": self.events_description,
            "eventFilters": self.events_filter,
            "eventReq": {},  # TO IMPROVE !!!
            "notificationDestination": f"{self.capif_callback_url}",
            "requestTestNotification": True,
            "websockNotifConfig": {
                "websocketUri": f"{self.capif_callback_url}",
                "requestWebsocketUri": True
            },
            "supportedFeatures": f"{self.supported_features}"
        }
        if os.path.exists(path):
            subscription = self._load_config_file(path)
            if not isinstance(subscription, dict):
                raise TypeError(f"Expected 'subscription' to be a dict, but got {type(subscription).__name__}")

            if subscriberId in subscription and name in subscription[subscriberId]:
                identifier = subscription[subscriberId][name]

                # Attempt to delete the subscription from CAPIF
                put_path = self.capif_https_url + f"capif-events/v1/{subscriberId}/subscriptions/{identifier}"

                try:
                    response = requests.put(
                        url=put_path,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        cert=(self.signed_key_crt_path, self.private_key_path),
                        verify=os.path.join(self.invoker_folder, "ca.crt")
                    )
                    response.raise_for_status()

                    self.logger.info(f"Successfully updated subscription for service '{name}'")

                except Exception as e:
                    self.logger.error("Unexpected error: %s", e)
                    return None, {"error": f"Unexpected error: {e}"}

            else:
                self.logger.warning(f"Service '{name}' not found for subscriber '{subscriberId}'")
                return None, {"error": f"Service '{name}' not found for subscriber '{subscriberId}'"}
        else:
            self.logger.error("Subscription file not found at path: %s", path)
            return None, {"error": "Subscription file not found"}

    def patch_subcription(self, name):
        self.update_subcription(self, name)


class capif_provider_event_feature(capif_provider_connector):
    
    def create_subscription(self, name, id):

        subscriberId = id

        path = self.capif_https_url + f"capif-events/v1/{subscriberId}/subscriptions"
        
        list_of_ids = self._load_provider_api_details()
        
        number = self._find_key_by_value(list_of_ids, id)

        payload = {
            "events": self.events_description,
            "eventFilters": self.events_filter,
            "eventReq": {},  # TO IMPROVE !!!
            "notificationDestination": f"{self.notification_destination}",
            "requestTestNotification": True,
            "websockNotifConfig": self.websock_notif_config,
            "supportedFeatures": f"{self.supported_features}"
        }
        
        number_low = number.lower()
        
        cert = (
            os.path.join(self.provider_folder, f"{number_low}.crt"),
            os.path.join(self.provider_folder, f"{number}_private_key.key"),
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
            
            location_header = response.headers.get("Location")

            if location_header:
                # Extrae el identificador de la URL en el encabezado 'Location'
                identifier = location_header.rstrip('/').split('/')[-1]
                self.logger.info(f"Subscriptionid obtained: {identifier}")
            else:
                self.logger.error("The Location header is not available in the response")

            path = os.path.join(self.provider_folder, "capif_subscriptions_id.json")

            # Load or initialize the subscription dictionary
            # Load or initialize the subscription dictionary
            if os.path.exists(path):
                subscription = self._load_config_file(path)
                if not isinstance(subscription, dict):
                    raise TypeError(f"Expected 'subscription' to be a dict, but got {type(subscription).__name__}")
            else:
                subscription = {}

            if not isinstance(subscriberId, (str, int)):
                raise TypeError(f"Expected 'subscriberId' to be a string or integer, but got {type(subscriberId).__name__}")

            # Convert events_description to a string if it isn't already
            if not isinstance(name, str):
                name = str(name)

            if str(subscriberId) not in subscription:
                # If the subscriberId is not in the subscription, create an empty dictionary for it
                subscription[str(subscriberId)] = {}
            # Update the subscription structure
            subscription[str(subscriberId)][name] = identifier

            # Save the updated dictionary back to the file
            self._create_or_update_file("capif_subscriptions_id", "json", subscription, "w")

        except Exception as e:
            self.logger.error("Unexpected error: %s", e)
            return None, {"error": f"Unexpected error: {e}"}
    
    def delete_subscription(self, name, id):
        subscriberId = id

        path = os.path.join(self.provider_folder, "capif_subscriptions_id.json")

        if os.path.exists(path):
            subscription = self._load_config_file(path)
            if not isinstance(subscription, dict):
                raise TypeError(f"Expected 'subscription' to be a dict, but got {type(subscription).__name__}")

            if subscriberId in subscription and name in subscription[subscriberId]:
                identifier = subscription[subscriberId][name]

                # Attempt to delete the subscription from CAPIF
                delete_path = self.capif_https_url + f"capif-events/v1/{subscriberId}/subscriptions/{identifier}"
                
                list_of_ids = self._load_provider_api_details()

                number = self._find_key_by_value(list_of_ids, id)
                
                number_low = number.lower()
        
                cert = (
                    os.path.join(self.provider_folder, f"{number_low}.crt"),
                    os.path.join(self.provider_folder, f"{number}_private_key.key"),
                )

                try:
                    response = requests.delete(
                        url=delete_path,
                        headers={"Content-Type": "application/json"},
                        cert=cert,
                        verify=os.path.join(self.provider_folder, "ca.crt")
                    )
                    response.raise_for_status()

                    # Remove the service entry from the subscription dictionary
                    del subscription[subscriberId][name]

                    # If no more services exist for the subscriber, remove the subscriber entry
                    if not subscription[subscriberId]:
                        del subscription[subscriberId]

                    # Save the updated dictionary back to the file
                    self._create_or_update_file("capif_subscriptions_id", "json", subscription, "w")

                    self.logger.info(f"Successfully deleted subscription for service '{name}'")

                except Exception as e:
                    self.logger.error("Unexpected error: %s", e)
                    return None, {"error": f"Unexpected error: {e}"}

            else:
                self.logger.warning(f"Service '{name}' not found for subscriber '{subscriberId}'")
                return None, {"error": f"Service '{name}' not found for subscriber '{subscriberId}'"}
        else:
            self.logger.error("Subscription file not found at path: %s", path)
            return None, {"error": "Subscription file not found"}
        
    def update_subcription(self, name, id):
        
        subscriberId = id
        
        path = os.path.join(self.provider_folder, "capif_subscriptions_id.json")
        
        list_of_ids = self._load_provider_api_details()
        
        number = self._find_key_by_value(list_of_ids, id)

        payload = {
            "events": self.events_description,
            "eventFilters": self.events_filter,
            "eventReq": {},  # TO IMPROVE !!!
            "notificationDestination": f"{self.notification_destination}",
            "requestTestNotification": True,
            "websockNotifConfig": self.websock_notif_config,
            "supportedFeatures": f"{self.supported_features}"
        }
        
        if os.path.exists(path):
            subscription = self._load_config_file(path)
            if not isinstance(subscription, dict):
                raise TypeError(f"Expected 'subscription' to be a dict, but got {type(subscription).__name__}")

            if subscriberId in subscription and name in subscription[subscriberId]:
                identifier = subscription[subscriberId][name]

                # Attempt to delete the subscription from CAPIF
                put_path = self.capif_https_url + f"capif-events/v1/{subscriberId}/subscriptions/{identifier}"
                
                list_of_ids = self._load_provider_api_details()

                number = self._find_key_by_value(list_of_ids, id)
                
                number_low = number.lower()
        
                cert = (
                    os.path.join(self.provider_folder, f"{number_low}.crt"),
                    os.path.join(self.provider_folder, f"{number}_private_key.key"),
                )

                try:
                    response = requests.put(
                        url=put_path,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        cert=cert,
                        verify=os.path.join(self.provider_folder, "ca.crt")
                    )
                    response.raise_for_status()

                    # Remove the service entry from the subscription dictionary
                    del subscription[subscriberId][name]

                    # If no more services exist for the subscriber, remove the subscriber entry
                    if not subscription[subscriberId]:
                        del subscription[subscriberId]

                    # Save the updated dictionary back to the file
                    self._create_or_update_file("capif_subscriptions_id", "json", subscription, "w")

                    self.logger.info(f"Successfully updated subscription for service '{name}'")

                except Exception as e:
                    self.logger.error("Unexpected error: %s", e)
                    return None, {"error": f"Unexpected error: {e}"}

            else:
                self.logger.warning(f"Service '{name}' not found for subscriber '{subscriberId}'")
                return None, {"error": f"Service '{name}' not found for subscriber '{subscriberId}'"}
        else:
            self.logger.error("Subscription file not found at path: %s", path)
            return None, {"error": "Subscription file not found"}

    def patch_subcription(self, name, id):
        self.update_subcription(self, name, id)