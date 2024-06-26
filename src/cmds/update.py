"""
'update' subcommand
"""

import src.vuln_manager as vuln_manager
import src.sc_manager as sc_manager
from src.logger_config import configure_logger
from src.config import get_global_config

logger = configure_logger("cmd_update")
config = get_global_config()


def handler(args):
    logger.debug("Updating local knowledge base")

    if not args.only_cve:
        logger.debug("Updating version manifest for upstream kernel source code")
        sc_manager.gen_version_manifest_upstream()

    if not args.only_sc:
        logger.debug("Updating vulnerability info")
        cves = vuln_manager.get_cve_list()
        cves = vuln_manager.diff_cve_list(cves)
        vuln_manager.get_cve_info_from_nvd_in_batch(cves, api_key=config.NVD_API_KEY)
        vuln_manager.gen_cve_manifest()
