"""
'enter' subcommand
"""

import pty
import os

from src.global_vars import *
from src.logger_config import configure_logger
import src.env_manager as env_manager

logger = configure_logger("cmd_enter")


def spawn_shell_with_dir(directory):
    # Check if the directory is valid
    if not os.path.isdir(directory):
        logger.error(f"Invalid directory {directory}")
        return

    os.chdir(directory)
    try:
        shell_env = os.environ['SHELL']
    except KeyError:
        # check if zsh is installed
        if os.path.isfile('/bin/zsh'):
            shell_env = '/bin/zsh'
        # check if bash is installed
        elif os.path.isfile('/bin/bash'):
            shell_env = '/bin/bash'
        else:
            shell_env = '/bin/sh'
    pty.spawn(shell_env)


def handler(args):
    env_id = env_manager.get_full_env_id(args.env_id)
    if env_id is None:
        logger.error(f"Env {args.env_id} not found")
        return
    env_dir = env_manager.get_env_dir(env_id)
    # spawn a new shell and enter the env dir
    spawn_shell_with_dir(env_dir)
    