"""
This file contains global variables that are used throughout the project.
"""

import os


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONFIG_FILE = f"{PROJECT_DIR}/config.yaml"

DB_DIR = f"{PROJECT_DIR}/db"
VULN_DESC_DIR = f"{DB_DIR}/vuln_desc"
VULN_DESC_FILE = f"{VULN_DESC_DIR}/items.yaml"
SC_DESC_DIR = f"{DB_DIR}/sc_desc"
SC_DESC_FILE = f"{SC_DESC_DIR}/upstream.yaml"
ENV_DESC_DIR = f"{DB_DIR}/env_desc"
KERNEL_BUILD_CONFIG_DIR = f"{ENV_DESC_DIR}/kernel_build_config"
KERNEL_BUILD_DEFAULT_CONFIG_FILE = f"{KERNEL_BUILD_CONFIG_DIR}/default.yaml"
KERNEL_BUILD_VULN_CONFIG_DIR = f"{KERNEL_BUILD_CONFIG_DIR}/vulns"

TOOLS_DIR = f"{PROJECT_DIR}/tools"
PATCHES_DIR = f"{TOOLS_DIR}/patches"
WORK_DIR = f"{PROJECT_DIR}/workdir"
LOG_DIR = f"{WORK_DIR}/logs"
ENV_DIR = f"{WORK_DIR}/envs"
ENV_KERNEL_SUBDIR = "kernel"
ENV_IMAGE_FILE = "rootfs.qcow2"
ENV_STARTUP_SCRIPT_FILE = "start.sh"
ENV_LOG_FILE = "vm.log"
ENV_RUNTIME_RECORD_FILE = ENV_DIR + "/envs.yaml"
ENV_COMMON_IMAGE_DIR = f"{WORK_DIR}/images"
ENV_COMMON_IMAGE_FILE = f"{ENV_COMMON_IMAGE_DIR}/rootfs.img"
ENV_COMMON_BASE_IMAGE_FILE = f"{ENV_COMMON_IMAGE_DIR}/rootfs-base.qcow2"
ENV_COMMON_PRIV_KEY_FILE = f"{ENV_COMMON_IMAGE_DIR}/id_rsa"

ENV_SSH_LOCAL_PORT_BASE = 10000
ENV_INTERNAL_IP_BASE = "10.0.2"
ENV_DEFAULT_USER = "user"

ENV_STATUS_INIT = "init"
ENV_STATUS_RUNNING = "running"
ENV_STATUS_STOPPED = "stopped"

RANGE_START_IN_WEIGHT = 0
RANGE_START_EX_WEIGHT = 1
RANGE_END_IN_WEIGHT = 2
RANGE_END_EX_WEIGHT = 4

PATCH_STATUS_FAIL = "fail"
PATCH_STATUS_SUCCESS = "success"
PATCH_STATUS_PATCHED = "patched"

BUILD_OPT_ALLYES = "allyesconfig"
BUILD_OPT_DEF = "defconfig"
BUILD_OPT_KJC = "kjc"

KERNEL_SOURCE_CODE_BASE_URL = "https://mirrors.edge.kernel.org/pub/linux/kernel"
KERNEL_OFFICIAL_GIT_BASE_URL = "https://git.kernel.org"
KERNEL_OFFICIAL_GIT_URL = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
)
KERNEL_OFFICIAL_COMMIT_BASE_URL = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id="
)
KERNEL_OFFICIAL_PATCH_BASE_URL = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id="
)
KERNEL_OFFICIAL_PATCH_FOR_FILE_URL_TMPL = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/{path}?id={commit}"
)
KERNEL_OFFICIAL_FILE_URL_TMPL = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/{path}?h=v{version}"
)
KERNEL_GITHUB_REPO_URL = "https://github.com/torvalds/linux.git"

NVD_REQUEST_ROLLING_TIME_WINDOW = 30  # in seconds
NVD_REQUEST_ROLLING_LIMIT = 50  # number of requests

VULN_BEGIN_YEAR = 2016

ENV_ID_LEN_FULL = 32
ENV_ID_LEN_SHORT = 16

LINUX_KERNEL_CPE = "cpe:2.3:o:linux:linux_kernel"

TQDM_BAR_FORMAT = "    {l_bar}{bar}{n}/{total}"

VER_MIN = "0"
VER_MAX = "99999999999"

# for vuln configs resolution
KCFG_GRAPH_NODE_CATEGORY_CONFIG = "config"
KCFG_GRAPH_NODE_CATEGORY_MENUCONFIG = "menuconfig"
KCFG_GRAPH_NODE_CATEGORY_MENU = "menu"
KCFG_GRAPH_NODE_TYPE_VIRTUAL = "virtual" # virtual node is not a real config
KCFG_GRAPH_NODE_TYPE_BOOL = "bool"
KCFG_GRAPH_NODE_TYPE_TRISTATE = "tristate"
KCFG_GRAPH_NODE_TYPE_STRING = "string"
KCFG_GRAPH_NODE_TYPE_INT = "int"
KCFG_GRAPH_NODE_TYPE_HEX = "hex"
KCFG_GRAPH_EDGE_TYPE_DEPEND = "depend"
KCFG_GRAPH_EDGE_TYPE_IF_DEPEND = "if_depend"
KCFG_GRAPH_EDGE_TYPE_MENU_DEPEND = "menu_depend"
KCFG_GRAPH_EDGE_TYPE_BOOL_IF_DEPEND = "bool_if_depend"
KCFG_GRAPH_EDGE_TYPE_CHOICE_DEPEND = "choice_depend"
KCFG_GRAPH_EDGE_TYPE_SELECT = "select"
KCFG_GRAPH_EDGE_TYPE_IMPLY = "imply"
KCFG_GRAPH_EDGE_TYPE_CHOICE_MUTEX = "choice_mutex"

# path mappings between root dirs and arch/ARCH dirs
SC_PATH_MAPPINGS = {
    'x86': {
        'virt/kvm': 'arch/x86/kvm', 'arch/x86/kvm': 'virt/kvm',
        'kernel': 'arch/x86/kernel', 'arch/x86/kernel': 'kernel',
        'mm': 'arch/x86/mm', 'arch/x86/mm': 'mm',
        'crypto': 'arch/x86/crypto', 'arch/x86/crypto': 'crypto',
        'net': 'arch/x86/net', 'arch/x86/net': 'net',
    }
}

CPU_VENDOR_INTEL = "INTEL"
CPU_VENDOR_AMD = "AMD"
CPU_VENDOR_ARM = "ARM"
CPU_VENDOR_UNKNOWN = "UNKNOWN"

# for alignment with Serendipity project
DEFAULT_KERNEL_BASE_ADDR = 0xFFFFFFFF81000000
KERNEL_DEP_FILE = "kernel_dep.h"

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"