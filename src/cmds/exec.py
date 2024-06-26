"""
'exec' subcommand
"""

from src.global_vars import *
import src.env_manager as env_manager
from src.logger_config import configure_logger

logger = configure_logger("cmd_exec")


def handler(args):
    env_id = env_manager.get_full_env_id(args.env_id)
    cmd = " ".join(args.cmd)
    if cmd.strip() == "":
        logger.error("Invalid command")
        return
    if env_id is None:
        logger.error("Invalid env id")
        return
    status = env_manager.get_env_entry(env_id)['status']
    if status != ENV_STATUS_RUNNING:
        logger.error(f"Env {args.env_id} is not running")
        return

    env_manager.exec_cmd_in_env(env_id, cmd)
