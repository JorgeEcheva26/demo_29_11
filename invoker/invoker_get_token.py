from opencapif_sdk import capif_invoker_connector, service_discoverer

capif_sdk_config_path = "./capif_sdk_config_sample_test.json"

invoker = capif_invoker_connector(capif_sdk_config_path)
invoker.onboard_invoker()
discoverer = service_discoverer(config_file=capif_sdk_config_path)
discoverer.discover_filter["api-name"] = "Project Management API"
discoverer.discover()
discoverer.get_tokens()
print(discoverer.token)