"""
This file provides utility functions.
"""

import secrets
import requests
from tqdm import tqdm
import subprocess
import math

from src.global_vars import *


def ensure_dir(path):
    """
    Ensure that the directory exists.
    """
    import os
    if not os.path.exists(path):
        os.makedirs(path)


def contain_str(needle, string):
    """
    Check if the string contains the needle.
    """
    return string and needle in string


def generate_random_id(length=ENV_ID_LEN_FULL):
    """
    Generate a random id.
    """
    return secrets.token_hex(length)


def download_file(url, save_path):
    """
    Download a file at url and save it to save_path.
    """
    response = requests.get(url, stream=True)
    total_size_in_bytes = int(response.headers.get('content-length', 0))
    block_size = 1024 * 1024 # 1 MB
    total_size_in_mb = math.ceil(total_size_in_bytes / block_size)
    progress_bar = tqdm(total=total_size_in_mb, unit='MB', unit_scale=True, ncols=60, bar_format=TQDM_BAR_FORMAT)

    with open(save_path, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(math.ceil(len(data) / block_size))
            file.write(data)
    
    progress_bar.close()
    
    if total_size_in_bytes != 0 and progress_bar.n != total_size_in_mb:
        return False

    return True


def save_file(content, save_path, binary=False):
    """
    Save content to save_path.
    """
    with open(save_path, "wb" if binary else "w") as f:
        f.write(content)


def run_cmd_get_stdout(cmd):
    """
    Run a command and return its stdout.
    """
    p = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    stdout, _ = p.communicate()
    return stdout


def get_pjt_rel_path(abs_path):
    """
    Get the relative path of a file.
    """
    return os.path.relpath(abs_path, PROJECT_DIR)


def get_descendants_by_edge_type(G, start, edge_type):
    """
    Get all descendants of a node in a directed graph following edges of a specific type.
    """
    visited = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node not in visited:
            visited.add(node)
            neighbors = (n for n, data in G[node].items() if data.get('type') == edge_type)
            stack.extend(neighbors)
    visited.remove(start)
    return visited


def get_cpu_vendor():
    """
    Detects the vendor of the host CPU.
    """
    try:
        with open('/proc/cpuinfo', 'r') as file:
            for line in file:
                if "vendor_id" in line:
                    if "GenuineIntel" in line:
                        return CPU_VENDOR_INTEL
                    elif "AuthenticAMD" in line:
                        return CPU_VENDOR_AMD
                    break
    except FileNotFoundError:
        pass

    return None
