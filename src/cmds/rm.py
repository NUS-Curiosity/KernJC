"""
'rm' subcommand
"""

from src.global_vars import *
from src.logger_config import configure_logger
import src.env_manager as env_manager

logger = configure_logger("cmd_rm")


def handler(args):
    """
    "env_id", help="id(s) of the vuln env(s) to be removed", metavar="ENV_ID", nargs='+'
    """
    if args.env_id is None:
        logger.error("No env id(s) specified")
        return
    for a_id in args.env_id:
        env_id = env_manager.get_full_env_id(a_id)
        if env_id is None:
            logger.error(f"Env {args.env_id} not found")
            return
        short_id = env_manager.get_short_env_id(env_id)
        record = env_manager.get_env_entry(env_id)
        if record is None:
            logger.error(f"Env {env_id} not found")
            return
        if record['status'] == ENV_STATUS_RUNNING:
            if args.force:
                env_manager.stop_env(env_id)
            else:
                logger.error(f"Env {env_id} is running. Stop it first.")
                return

        env_manager.remove_env_entry(env_id)
        env_manager.remove_env_dir(env_id)
        logger.info(f"Env {short_id} removed")
