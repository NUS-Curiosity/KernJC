"""
'ps' subcommand
"""

from prettytable import PrettyTable

from src.logger_config import configure_logger
import src.env_manager as env_manager

logger = configure_logger("cmd_ps")


def handler(args):
    envs = env_manager.get_env_entries()
    if envs is None:
        return
    table = PrettyTable()
    table.field_names = ["ID", "CVE", "Kernel", "Status"]
    for env_id, record in envs.items():
        if not args.all and record["status"] != env_manager.ENV_STATUS_RUNNING:
            continue
        table.add_row(
            [
                env_manager.get_short_env_id(env_id),
                record["cve"],
                record["kernel_version"],
                record["status"],
            ]
        )
    table.align = "l"
    print(table)
