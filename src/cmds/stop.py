"""
'stop' subcommand
"""

from src.global_vars import *
import src.env_manager as env_manager
from src.logger_config import configure_logger

logger = configure_logger("cmd_stop")


def handler(args):
    env_id = env_manager.get_full_env_id(args.env_id)
    if env_id is None:
        logger.error("Invalid env id")
        return
    status = env_manager.get_env_entry(env_id)['status']
    if status == ENV_STATUS_STOPPED:
        logger.warning(f"Env {args.env_id} is already stopped")
        return
    if status != ENV_STATUS_RUNNING:
        logger.error(f"Env {args.env_id} is in an unknown state ({status})")
        return
    
    logger.debug(f"Stopping env {args.env_id}")
    env_manager.stop_env(env_id)
