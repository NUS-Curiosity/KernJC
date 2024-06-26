"""
'start' subcommand
"""

from src.global_vars import *
import src.env_manager as env_manager
from src.logger_config import configure_logger

logger = configure_logger("cmd_start")


def handler(args):
    """
    env_id             id of the vuln env to be started
    -m MEM, --mem MEM  memory size (default: 2G)
    -smp CPU_NUM       number of CPUs (default: 2,cores=1)
    -cpu CPU           CPU model (default: host,+smep,+smap)
    -kaslr on/off      enable KASLR (default: on)
    -fgkaslr on/off    enable FGKASLR (default: on)
    -smep on/off       enable SMEP (default: on)
    -smap on/off       enable SMAP (default: on)
    -kpti on/off       enable KPTI (default: on)
    -enable-kvm        enable KVM full virtualization support
    -opts OPTS         specify more QEMU options
    -append STRING     append a string to the kernel command line
    --reuse            reuse previous options (if you have started the env before)
    """
    env_id = env_manager.get_full_env_id(args.env_id)
    if env_id is None:
        logger.error("Invalid env id")
        return
    status = env_manager.get_env_entry(env_id)['status']
    if status == ENV_STATUS_RUNNING:
        logger.warning(f"Env {args.env_id} is already running")
        return
    if status == ENV_STATUS_INIT:
        logger.error(f"Env {args.env_id} seems broken")
        logger.error("Please try to remove it and create a new one")
        return
    if status != ENV_STATUS_STOPPED:
        logger.error(f"Env {args.env_id} is in an unknown state ({status})")
        return
    if args.enable_kvm:
        # check if kvm is supported
        if not os.path.exists("/dev/kvm"):
            logger.error("KVM is not supported on this machine")
            return
        # check if kvm is enabled
        if not os.path.exists("/sys/module/kvm"):
            logger.error("KVM is not enabled on this machine")
            return
    if args.reuse:
        logger.debug("Reusing previous startup options")
        context = None
    else:
        context = {
            "mem": args.mem,
            "smp": args.smp,
            "cpu": args.cpu,
            "kaslr": args.kaslr,
            "fgkaslr": args.fgkaslr,
            "smep": args.smep,
            "smap": args.smap,
            "kpti": args.kpti,
            "enable_kvm": args.enable_kvm,
            "opts": args.opts,
            "append": args.append,
        }
    logger.debug(f"Starting env {args.env_id}")
    env_manager.start_env(env_id, context=context)
