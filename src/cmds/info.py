"""
'info' subcommand
"""

from pprint import pprint

import src.env_manager as env_manager
from src.global_vars import *
from src.logger_config import configure_logger

logger = configure_logger("cmd_info")


def handler(args):
    env_id = env_manager.get_full_env_id(args.env_id)
    if env_id is None:
        logger.error("Invalid env id")
        return
    env_entry = env_manager.get_env_entry(env_id)
    pprint(env_entry)
