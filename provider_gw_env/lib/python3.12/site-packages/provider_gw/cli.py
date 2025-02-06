import click
import logging
from provider_gw.provider_gw import provider_gw


# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("provider_gw_cli")


@click.group()
def cli():
    """CLI para gestionar Provider_gw"""
    pass


@cli.command()
@click.option("--debug", is_flag=True, help="Enable debug mode.")
@click.argument("northbound_yaml", default="./northbound.yaml", type=click.Path(exists=True))
@click.argument("southbound_yaml", default="./southbound.yaml", type=click.Path(exists=True))
def start(northbound_yaml, southbound_yaml, debug):
    """Inicia el gateway con los archivos YAML especificados."""
    logger.info(f"Starting Provider_gw with {northbound_yaml} and {southbound_yaml}")
    try:
        gw = provider_gw(northbound_yaml, southbound_yaml, debug)
        gw.start()
        logger.info("Provider_gw started successfully.")
    except Exception as e:
        logger.error(f"Failed to start Provider_gw: {e}")


@cli.command()
@click.option("--debug", is_flag=True, help="Enable debug mode.")
@click.argument("northbound_yaml", default="./northbound.yaml", type=click.Path(exists=True))
@click.argument("southbound_yaml", default="./southbound.yaml", type=click.Path(exists=True))
def run(northbound_yaml, southbound_yaml, debug):
    """Ejecuta el gateway sin inicializarlo."""
    logger.info(f"Running Provider_gw with {northbound_yaml} and {southbound_yaml}")
    try:
        gw = provider_gw(northbound_yaml, southbound_yaml, debug)
        gw.run()
        logger.info("Provider_gw is running.")
    except Exception as e:
        logger.error(f"Failed to run Provider_gw: {e}")


@cli.command()
@click.option("--debug", is_flag=True, help="Enable debug mode.")
@click.argument("northbound_yaml", default="./northbound.yaml", type=click.Path(exists=True))
@click.argument("southbound_yaml", default="./southbound.yaml", type=click.Path(exists=True))
def remove(northbound_yaml, southbound_yaml, debug):
    """Elimina todos los recursos y apaga el gateway."""
    logger.info(f"Removing Provider_gw with {northbound_yaml} and {southbound_yaml}")
    try:
        gw = provider_gw(northbound_yaml, southbound_yaml, debug)
        gw.remove()
        logger.info("Provider_gw resources removed successfully.")
    except Exception as e:
        logger.error(f"Failed to remove Provider_gw: {e}")


@cli.command()
@click.option("--debug", is_flag=True, help="Enable debug mode.")
@click.argument("northbound_yaml", default="./northbound.yaml", type=click.Path(exists=True))
@click.argument("southbound_yaml", default="./southbound.yaml", type=click.Path(exists=True))
def refresh(northbound_yaml, southbound_yaml, debug):
    """Refresca el token del southbound"""
    logger.info(f"Removing Provider_gw with {northbound_yaml} and {southbound_yaml}")
    try:
        gw = provider_gw(northbound_yaml, southbound_yaml, debug)
        gw.refresh()
        logger.info("Provider_gw resources removed successfully.")
    except Exception as e:
        logger.error(f"Failed to remove Provider_gw: {e}")


def main():
    cli()
