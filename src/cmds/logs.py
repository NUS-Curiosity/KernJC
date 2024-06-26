"""
'logs' subcommand
"""

import src.env_manager as env_manager
from src.global_vars import *
from src.logger_config import configure_logger

logger = configure_logger("cmd_logs")


def handler(args):
    env_id = env_manager.get_full_env_id(args.env_id)
    if env_id is None:
        logger.error("Invalid env id")
        return
    env_path = env_manager.get_env_dir(env_id)
    log_file = f"{env_path}/vm.log"
    if not os.path.exists(log_file):
        logger.error(f"Log file does not exist in env {env_manager.get_short_env_id(env_id)}")
        return
    # also deal with -f --follow
    if args.follow:
        os.system(f"tail -f {log_file}")
        return
    # no -f --follow
    with open(log_file, "r") as f:
        print(f.read())
