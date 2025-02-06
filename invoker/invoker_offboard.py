from opencapif_sdk import capif_invoker_connector

capif_sdk_config_path = "./capif_sdk_config_sample_test.json"

invoker = capif_invoker_connector(capif_sdk_config_path)
invoker.offboard_invoker()
