"""
'query' subcommand
"""

import sys
from pprint import pprint

import src.env_manager as env_manager
from src.logger_config import configure_logger
from src.global_vars import *
import src.vuln_manager as vuln_manager
import src.sc_manager as sc_manager


logger = configure_logger("cmd_query")


def handler(args):
    cve = args.cve.upper()
    info = vuln_manager.get_cve_info(cve)
    if not info:
        sys.exit(-1)
    if not (args.check_vuln_nvd or args.check_vuln_patch or args.list_cfg):
        logger.debug(f"Querying info for {cve}")
        pprint(info)
        return
    if args.list_cfg:
        temp_env_built = False
        if args.env is None:
            logger.debug(f"No env specified, creating a new one for {cve}")
            kernel_version = vuln_manager.get_cve_candidate_kernel_version(cve=cve)
            if kernel_version is None:
                if args.kernel is None:
                    logger.error(f"Cannot find a candidate kernel version for {cve}")
                    logger.error("Please specify a kernel version with -k/--kernel")
                    return
                else:
                    kernel_version = args.kernel
                    if not sc_manager.validate_kernel_version(kernel_version):
                        logger.error(f"Invalid kernel version ({kernel_version})")
                        return
            env_id = env_manager.init_env(cve=cve, kernel_version=kernel_version)
            env_path = env_manager.get_env_dir(env_id=env_id)
            sc_manager.download_kernel_source_code(version=kernel_version, path=env_path)
            temp_env_built = True
        else:
            env_id = env_manager.get_full_env_id(args.env)
        if env_id is None:
            logger.error("Invalid env id")
            sys.exit(-1)

        cfgs = vuln_manager.get_cve_cfgs(cve, env_id, arch=args.arch, print_out=True)
        if cfgs is None or len(cfgs) == 0:
            logger.warning(f"Cannot get {cve} related kernel configs")
            # return
        # logger.info(f"Kernel configs related to {cve}:")
        # for cfg in cfgs:
        #     print(f"CONFIG_{cfg}")
        
        if temp_env_built:
            env_manager.remove_env_entry(env_id)
            env_manager.remove_env_dir(env_id)

        return

    # check if a vuln exists in a kernel version
    if args.kernel_version is None:
        logger.error("Please specify a kernel version")
        sys.exit(-1)
    if sc_manager.validate_kernel_version(args.kernel_version) is False:
        logger.error("Invalid kernel version")
        sys.exit(-1)
    if args.check_vuln_nvd:
        status = vuln_manager.check_version_vuln_using_range(cve, args.kernel_version)
        if status is None:
            logger.error(f"Failed to check {cve} using NVD data")
        elif status:
            logger.warning(f"v{args.kernel_version} kernel is vulnerable to {cve}")
        else:
            logger.info(f"v{args.kernel_version} kernel is not vulnerable to {cve}")
        return
    if args.check_vuln_patch:
        try:
            patch = info['patch']
            _ = patch[0]
        except (KeyError, IndexError):
            logger.error(f"Failed to check {cve} using patch")
            return
        res = vuln_manager.check_version_vuln_using_patch(cve, args.kernel_version)
        for commit, status in res.items():
            if PATCH_STATUS_FAIL in status:
                logger.error(f"Failed to check v{args.kernel_version} kernel against commit {commit}")
                continue
            if PATCH_STATUS_PATCHED in status:
                logger.info(f"v{args.kernel_version} kernel is (partly) patched by commit {commit}")
                continue
            if PATCH_STATUS_SUCCESS in status:
                logger.warning(f"v{args.kernel_version} kernel is not patched by commit {commit}")
                continue
        return
