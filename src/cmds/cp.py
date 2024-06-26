"""
'cp' subcommand
"""

import src.env_manager as env_manager
from src.global_vars import *
from src.logger_config import configure_logger

logger = configure_logger("cmd_cp")


def handler(args):
    src = args.src
    dst = args.dst
    from_env_to_local = False
    # check which is the env, src or dst
    if ":" in src: # src is env, dst is local
        short_env_id = src.split(":")[0]
        real_src = src.split(":")[1]
        real_dst = dst
        from_env_to_local = True
    elif ":" in dst: # src is local, dst is env
        short_env_id = dst.split(":")[0]
        real_src = src
        real_dst = dst.split(":")[1]
    else:
        logger.error("Invalid src or dst")
        return

    env_id = env_manager.get_full_env_id(short_env_id)
    if env_id is None:
        logger.error("Invalid env id")
        return

    status = env_manager.get_env_entry(env_id)['status']
    if status != ENV_STATUS_RUNNING:
        logger.error(f"Env {short_env_id} is not running")
        return
    
    if from_env_to_local:
        env_manager.copy_file_from_env(env_id, real_src, real_dst)
    else:
        env_manager.copy_file_to_env(env_id, real_src, real_dst)
