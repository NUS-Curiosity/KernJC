"""
This file provides functions to manage envs.
"""

import shutil
import sys
import pty
import socket
import getpass
import yaml
import os
import signal
import time
import subprocess

import src.vuln_manager as vuln_manager
from src.util import ensure_dir, generate_random_id
from src.global_vars import *
from src.logger_config import configure_logger

logger = configure_logger("env_manager")


def allocate_port():
    """
    Allocate a port.
    """
    # check start from ENV_SSH_LOCAL_PORT_BASE and return the first available port
    for port in range(ENV_SSH_LOCAL_PORT_BASE, 65536):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex(("localhost", port))
            if result != 0:
                return port


def allocate_ip(env_id):
    """
    Allocate an IP address.
    """
    envs = get_env_entries()
    used_ip = set()
    for env in envs:
        if env == env_id:
            continue
        try:
            used_ip.add(envs[env]["ip"])
        except KeyError:
            pass
    # check start from ENV_INTERNAL_IP_BASE and return the first available IP
    for i in range(10, 256):
        ip = f"{ENV_INTERNAL_IP_BASE}.{i}"
        if ip not in used_ip:
            return ip


def add_env_entry(env_id, record):
    """
    Add an env entry to the local record.
    """
    # load the local yaml record
    try:
        with open(ENV_RUNTIME_RECORD_FILE, "r") as f:
            envs = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Env record file not found. Creating a new one.")
        envs = dict()
    # add the entry, and dump it back
    envs[env_id] = record
    with open(ENV_RUNTIME_RECORD_FILE, "w") as f:
        yaml.dump(envs, f, default_flow_style=False)


def update_env_entry(env_id, record):
    """
    Update an env entry in the local record.
    """
    # load the local yaml record
    try:
        with open(ENV_RUNTIME_RECORD_FILE, "r") as f:
            envs = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("Env record file not found")
        return
    # update the entry, and dump it back
    try:
        envs[env_id].update(record)
    except KeyError:
        logger.error(f"Env {get_short_env_id(env_id)} not found in local record")
        return
    with open(ENV_RUNTIME_RECORD_FILE, "w") as f:
        yaml.dump(envs, f, default_flow_style=False)


def get_env_entry(env_id):
    """
    Get an env entry from the local record.
    """
    # load the local yaml record
    try:
        with open(ENV_RUNTIME_RECORD_FILE, "r") as f:
            envs = yaml.safe_load(f)
    except FileNotFoundError:
        return None
    # get the entry
    try:
        return envs[env_id]
    except KeyError:
        return None


def get_env_entries():
    """
    Get all env entries from the local record.
    """
    # load the local yaml record
    try:
        with open(ENV_RUNTIME_RECORD_FILE, "r") as f:
            envs = yaml.safe_load(f)
    except FileNotFoundError:
        return None
    # get the entries
    return envs


def get_full_env_id(short_id):
    """
    Get the full id of an env.
    """
    res = list()
    # load the local yaml record
    try:
        with open(ENV_RUNTIME_RECORD_FILE, "r") as f:
            envs = yaml.safe_load(f)
    except FileNotFoundError:
        return None
    # get the full id
    for env_id in envs:
        if env_id.startswith(short_id):
            res.append(env_id)
    if len(res) == 1:
        return res[0]
    elif len(res) == 0:
        return None
    else:
        logger.error(f"Env {short_id} is ambiguous")
        sys.exit(-1)


def get_short_env_id(full_id):
    """
    Get the short id of an env.
    """
    return full_id[:ENV_ID_LEN_SHORT]


def set_env_entry_status(env_id, status):
    """
    Set the status of an env entry in the local record.
    """
    # load the local yaml record
    try:
        with open(ENV_RUNTIME_RECORD_FILE, "r") as f:
            envs = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("Env record file not found")
        return
    # set the status
    try:
        envs[env_id]["status"] = status
    except KeyError:
        logger.error(f"Env {get_short_env_id(env_id)} not found in local record")
        return
    # dump it back
    with open(ENV_RUNTIME_RECORD_FILE, "w") as f:
        yaml.dump(envs, f, default_flow_style=False)


def remove_env_entry(env_id):
    """
    Remove an env entry from the local record.
    """
    # load the local yaml record
    try:
        with open(ENV_RUNTIME_RECORD_FILE, "r") as f:
            envs = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Env record file not found")
        return
    # remove the entry, and dump it back
    try:
        envs.pop(env_id)
    except KeyError:
        logger.warning(f"Env {get_short_env_id(env_id)} not found in local record")
        return
    with open(ENV_RUNTIME_RECORD_FILE, "w") as f:
        yaml.dump(envs, f, default_flow_style=False)


def init_env(cve, kernel_version):
    """
    Initialize an env.
    """
    logger.debug("Initializing env")
    # generate unique env id ()
    while True:
        env_id = generate_random_id()
        short_id = get_short_env_id(env_id)
        # make sure short_id is unique
        if get_full_env_id(short_id) is None:
            break

    # create env dir
    ensure_dir(ENV_DIR + "/" + env_id)
    # create env entry
    record = {
        "status": ENV_STATUS_INIT,
        "kernel_version": kernel_version,
        "cve": cve,
        "pid": None,
        "ip": None,
        "port": None,
        "create_time": time.time(),
    }
    add_env_entry(env_id, record)
    return env_id


def load_qemu_startup_command(env_id):
    """
    Load the startup command of an env.
    """
    env_dir = get_env_dir(env_id)
    command = list()
    try:
        with open(f"{env_dir}/{ENV_STARTUP_SCRIPT_FILE}", "r") as f:
            res = f.read().split("\\\n")
            # remove #!/bin/bash
            res[0] = res[0].split("\n")[-1]
    except FileNotFoundError:
        logger.error(f"Startup script for env {get_short_env_id(env_id)} not found")
        exit(-1)
    first_line = 0
    for i, line in enumerate(res):
        temp_line = line.strip()
        if temp_line.startswith("qemu-system-x86_64"):
            command.append(temp_line)
            first_line = i
            break
        if temp_line.startswith("sudo"):
            key, value = temp_line.split(" ", 1)
            command.extend([key, value])
            first_line = i
            break
    for line in res[first_line + 1 :]:
        temp_line = line.strip()
        if temp_line == "":
            continue
        try:
            key, value = temp_line.split(" ", 1)
            if key == "-append":
                value = value.replace('"', "")
            command.extend([key, value])
        except ValueError:
            command.append(temp_line)
    return command


def save_qemu_startup_command(env_id, command):
    """
    Save the startup command of an env for reuse.
    """
    env_dir = get_env_dir(env_id)
    with open(f"{env_dir}/{ENV_STARTUP_SCRIPT_FILE}", "w") as f:
        f.write("#!/bin/bash\n")
        skip = False
        skip_to__kernel = False
        for idx, entry in enumerate(command):
            if entry == "-kernel":
                skip_to__kernel = False
            if skip_to__kernel:
                continue
            if skip:
                skip = False
                continue
            if entry in [
                "-m",
                "-smp",
                "-cpu",
                "-kernel",
                "-drive",
                "-net",
                "sudo",
            ]:
                f.write(f"{entry} {command[idx+1]} \\\n")
                skip = True
            elif entry == "-append":
                kernel_idx = command.index("-kernel")
                f.write(f"{entry} \"{' '.join(command[idx+1:kernel_idx])}\" \\\n")
                skip_to__kernel = True
            else:
                f.write(f"{entry} \\\n")


def start_qemu_vm(env_id, command):
    """
    Start a QEMU VM with given command.
    """
    log_file = get_env_dir(env_id) + "/" + ENV_LOG_FILE

    if not os.access("/dev/kvm", os.W_OK) and command[0] == "sudo":
        command.insert(1, "-S")
        sudo_password = getpass.getpass(
            prompt=f"[sudo] password for {getpass.getuser()}:"
        )
        with open(log_file, "w") as f:
            process = subprocess.Popen(
                command,
                stdout=f,
                stderr=f,
                stdin=subprocess.PIPE,
                universal_newlines=True,
            )
            process.stdin.write(sudo_password + "\n")
            process.stdin.flush()
    else:
        with open(log_file, "w") as f:
            process = subprocess.Popen(
                command, stdout=f, stderr=f, universal_newlines=True
            )
    return process.pid


def start_env(env_id, context=None):
    """
    Start an env.
    """
    if context is None:
        # load startup script from file
        command = load_qemu_startup_command(env_id)
        # update the port number
        ip = allocate_ip(env_id)
        port = allocate_port()
        for idx, line in enumerate(command):
            if line.startswith("user,host="):
                command[idx] = f"user,host={ip},hostfwd=tcp:127.0.0.1:{port}-:22"
                break
    else:
        # generate startup command and save it to file for reuse
        # TODO: currently we hardcode parts of the command, but we should
        #       make them configurable or more flexible in the future
        command = list()
        # check if current user has permission to use kvm
        if not os.access("/dev/kvm", os.W_OK):
            command.append("sudo")
        command.append("qemu-system-x86_64")
        command.append("-m")
        command.append(context["mem"])
        command.append("-smp")
        command.append(context["smp"])
        command.append("-cpu")
        command.append(context["cpu"])
        if context["enable_kvm"]:
            command.append("-enable-kvm")
        _append = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 no_hash_pointers"
        _append += " kaslr" if context["kaslr"] else " nokaslr"
        _append += " fgkaslr" if context["fgkaslr"] else " nofgkaslr"
        _append += " smep" if context["smep"] else " nosmep"
        _append += " smap" if context["smap"] else " nosmap"
        _append += " kpti=1" if context["kpti"] else " nopti"
        _append += " " + f" {context['append']}".strip()
        command.append("-append")
        command.append(_append)
        command.append("-kernel")
        command.append(
            f"{get_env_dir(env_id)}/{ENV_KERNEL_SUBDIR}/arch/x86/boot/bzImage"
        )
        command.append("-drive")
        command.append(f"file={get_env_dir(env_id)}/{ENV_IMAGE_FILE},format=qcow2")
        command.append("-net")
        ip = allocate_ip(env_id)
        port = allocate_port()
        command.append(f"user,host={ip},hostfwd=tcp:127.0.0.1:{port}-:22")
        command.append("-net")
        command.append("nic,model=e1000")
        command.append("-nographic")
        if context["opts"] != "":
            for opt in context["opts"].split(" "):
                command.append(opt)
    save_qemu_startup_command(env_id, command)
    pid = start_qemu_vm(env_id, command)
    logger.info(f"Started env {get_short_env_id(env_id)} (QEMU pid: {pid})")
    part_record = {
        "pid": pid,
        "ip": ip,
        "port": port,
        "status": ENV_STATUS_RUNNING,
    }
    update_env_entry(env_id, part_record)


def stop_env(env_id):
    """
    Stop an env.
    """
    # get qemu process pid
    try:
        pid = get_env_entry(env_id)["pid"]
    except KeyError:
        logger.error(f"PID of env {get_short_env_id(env_id)} not found in local record")
        return
    # kill qemu process
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        logger.warning(f"QEMU process {pid} not found")
    except PermissionError:
        os.system(f"sudo kill {pid}")
    # update local record
    set_env_entry_status(env_id, ENV_STATUS_STOPPED)


def get_env_dir(env_id):
    """
    Get the directory of an env.
    """
    return ENV_DIR + "/" + env_id


def remove_env_dir(env_id):
    """
    Remove the directory of an env.
    """
    env_dir = get_env_dir(env_id)
    shutil.rmtree(env_dir)


def apply_custom_config(env_id):
    """
    Apply custom config to kernel source code's .config.
    """
    logger.debug("Applying custom config")
    # get associated cve
    cve = get_env_entry(env_id)["cve"]
    # load default config
    logger.debug("Loading default custom config")
    with open(f"{KERNEL_BUILD_DEFAULT_CONFIG_FILE}", "r") as f:
        res_config = yaml.safe_load(f)
    # generate configs for CVE based on kcfg graph
    logger.debug("Generating potential configs based on kcfg graph")
    start_time = time.time()
    kcfgs = vuln_manager.get_cve_cfgs(cve=cve, env_id=env_id, arch="x86")
    end_time = time.time()
    logger.info(f"Config identification time: {end_time - start_time} seconds")
    if kcfgs:
        # TODO: currently we only consider "y"
        kcfgs_dict = {f"CONFIG_{kcfg}": "y" for kcfg in kcfgs}
        logger.info(f"Found {len(kcfgs_dict)} potential configs based on kcfg graph")
        res_config.update(kcfgs_dict)
    # load cve related config, if any
    cve_config = None
    logger.debug(f"Loading {cve} related custom config")
    try:
        with open(f"{KERNEL_BUILD_VULN_CONFIG_DIR}/{cve}.yaml", "r") as f:
            cve_config = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"Vuln config file not found. Using default config.")
        pass
    if cve_config is not None:
        res_config.update(cve_config)
    # load .config
    logger.debug("Merging custom config with .config")
    with open(f"{get_env_dir(env_id)}/{ENV_KERNEL_SUBDIR}/.config", "r") as f:
        dot_config = f.read()
    # convert dot_config to dict
    dot_config_dict = dict()
    for line in dot_config.split("\n"):
        if line.startswith("#") or line == "":
            continue
        try:
            key, value = line.split("=", 1)
        except ValueError:
            logger.warning(f"Invalid line in .config: {line}")
            continue
        dot_config_dict[key] = value
    # apply res_config to dot_config_dict
    dot_config_dict.update(res_config)
    # convert dot_config_dict to dot_config and dump it back
    with open(f"{get_env_dir(env_id)}/{ENV_KERNEL_SUBDIR}/.config", "w") as f:
        for key in dot_config_dict:
            f.write(f"{key}={dot_config_dict[key]}\n")
    logger.info("Applied custom config")


def build_kernel(env_id, opt=BUILD_OPT_KJC):
    """
    Build Linux kernel source code.
    """
    logger.debug("Building kernel source code")
    sr_dir = f"{get_env_dir(env_id)}/{ENV_KERNEL_SUBDIR}"

    # all patches have been moved into tools/patches
    # we change the following code into a for loop
    # see tools/patches/README.md for more details
    os.system(f"cp {PATCHES_DIR}/*.patch {sr_dir}")
    os.chdir(sr_dir)
    # apply files except for .md files
    for file in os.listdir(PATCHES_DIR):
        if file.endswith(".md"):
            continue
        logger.debug(f"Applying patch {file}")
        os.system(f"patch -p1 --batch --forward < {file}")

    try:
        if opt == BUILD_OPT_ALLYES:
            logger.debug("Building kernel with allyesconfig")
            subprocess.run(["make", "allyesconfig"], check=True)
        elif opt == BUILD_OPT_DEF:
            logger.debug("Building kernel with defconfig")
            subprocess.run(["make", "defconfig"], check=True)
        else:
            logger.debug("Building kernel with kjc config")
            subprocess.run(["make", "defconfig"], check=True)
            apply_custom_config(env_id)
            subprocess.run(["make", "olddefconfig"], check=True)

        start_time = time.time()
        subprocess.run(["make", "-j$(nproc)"], shell=True, check=True)
        end_time = time.time()
        logger.info(f"Kernel build time: {end_time - start_time} seconds")

        logger.info("Built kernel source code")

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error code {e.returncode}")
        exit(-1)


# TODO: use this function in cmds
def clean_kernel_build(sr_dir):
    """
    Clean kernel build.
    """
    os.chdir(sr_dir)
    os.system("make clean")
    logger.info("Cleaned kernel build")


def kernel_already_built(env_id):
    """
    Check if the kernel source code has already been built.
    """
    sr_dir = f"{get_env_dir(env_id)}/{ENV_KERNEL_SUBDIR}"
    return os.path.exists(f"{sr_dir}/arch/x86/boot/bzImage")


def prepare_rootfs(env_id):
    """
    Prepare rootfs for the given env.
    """
    # use qemu-img to create an overlay image based on the base image
    # so that the base image is not modified
    logger.debug("Preparing rootfs (overlay image)")
    if not os.path.exists(ENV_COMMON_IMAGE_FILE):
        logger.error("Rootfs base image not found")
        logger.error("Please run tools/create-image.sh first")
        sys.exit(1)
    env_dir = get_env_dir(env_id)
    try:
        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-o",
                f"backing_file={ENV_COMMON_BASE_IMAGE_FILE},backing_fmt=qcow2",
                f"{env_dir}/{ENV_IMAGE_FILE}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create overlay image with qemu-img")
        exit(-1)


def exec_cmd_in_env(env_id, cmd):
    """
    Execute a command in the specific env.
    """
    env_port = get_env_entry(env_id)["port"]
    command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {ENV_COMMON_PRIV_KEY_FILE} -p {env_port} {ENV_DEFAULT_USER}@localhost {cmd}"
    subprocess.run(command, shell=True)


def get_interactive_shell(env_id):
    """
    Get an interactive shell in the specific env.
    """
    env_port = get_env_entry(env_id)["port"]
    command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {ENV_COMMON_PRIV_KEY_FILE} -p {env_port} {ENV_DEFAULT_USER}@localhost"
    pty.spawn(["/bin/bash", "-c", command])


def copy_file_to_env(env_id, src, dst):
    """
    Copy a file from host to the specific env.
    """
    env_port = get_env_entry(env_id)["port"]
    command = f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {ENV_COMMON_PRIV_KEY_FILE} -P {env_port} {src} {ENV_DEFAULT_USER}@localhost:{dst}"
    subprocess.run(command, shell=True)


def copy_file_from_env(env_id, src, dst):
    """
    Copy a file from the specific env to host.
    """
    env_port = get_env_entry(env_id)["port"]
    command = f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {ENV_COMMON_PRIV_KEY_FILE} -P {env_port} {ENV_DEFAULT_USER}@localhost:{src} {dst}"
    subprocess.run(command, shell=True)
