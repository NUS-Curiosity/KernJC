"""
'build' subcommand
"""

import src.env_manager as env_manager
import time
import src.vuln_manager as vuln_manager
import src.sc_manager as sc_manager
from src.global_vars import *
from src.logger_config import configure_logger

logger = configure_logger("cmd_build")


def handler(args):
    cve = args.cve.upper()
    if args.allyesconfig:
        opt = BUILD_OPT_ALLYES
    elif args.defconfig:
        opt = BUILD_OPT_DEF
    else:
        opt = BUILD_OPT_KJC
    if args.kernel is None:
        # try to get a candidate kernel version
        kernel_version = vuln_manager.get_cve_candidate_kernel_version(cve=cve)
        if kernel_version is None:
            logger.error(f"Cannot find a candidate kernel version for {cve}")
            logger.error("Please specify a kernel version with -k/--kernel")
            return
        logger.info(f"Auto-selected kernel version: {kernel_version}")
    else:
        kernel_version = args.kernel
        # validate the kernel version
        if not sc_manager.validate_kernel_version(kernel_version):
            logger.error(f"Invalid kernel version: {kernel_version}")
            return
    
    env_id = env_manager.init_env(cve=cve, kernel_version=kernel_version)
    env_path = env_manager.get_env_dir(env_id=env_id)
    sc_manager.download_kernel_source_code(version=kernel_version, path=env_path)
    # measure the time for kernel build
    start_time = time.time()
    env_manager.build_kernel(env_id=env_id, opt=opt)
    end_time = time.time()
    logger.info(f"Kernel build time: {end_time - start_time} seconds with {opt} option for {cve}")
    env_manager.prepare_rootfs(env_id=env_id)
    env_manager.set_env_entry_status(env_id=env_id, status=env_manager.ENV_STATUS_STOPPED)
    
    logger.info(f"Env {env_manager.get_short_env_id(env_id)} created")
