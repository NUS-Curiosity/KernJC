"""
"""

import sys
import yaml

from src.global_vars import CONFIG_FILE
from src.logger_config import configure_logger

logger = configure_logger("config")
global_config = None


class Config:
    """
    This class is used to parse config file.
    """

    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = config_file
        try:
            with open(self.config_file, "r") as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Config file {self.config_file} not found")
            sys.exit(-1)
        self.NVD_API_KEY = config["NVD_API_KEY"]


def get_global_config():
    """
    Get global config.
    """
    global global_config
    if global_config is None:
        global_config = Config()
    return global_config
