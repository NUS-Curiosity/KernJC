"""
This file provides functions to manage source code information.
"""

import yaml
import sys
import re
import requests
from tqdm import tqdm
import networkx as nx
import tarfile
import packaging.version as ver
import sys
import os

from src.global_vars import *
from src.logger_config import configure_logger
from src.util import download_file, get_pjt_rel_path

logger = configure_logger("sc_manager")

global_version_manifest = None


def load_version_manifest():
    """
    Load version manifest from file.
    """
    global global_version_manifest
    if global_version_manifest is None:
        try:
            with open(SC_DESC_FILE, "r") as f:
                global_version_manifest = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Failed to load {SC_DESC_FILE}")
            sys.exit(-1)
        global_version_manifest = [
            version
            for major_version in global_version_manifest
            for version in global_version_manifest[major_version]
            if re.fullmatch(r"^[0-9]+(\.[0-9]+)*$", version)
        ]
        global_version_manifest = sorted(global_version_manifest, key=ver.parse)
    return global_version_manifest


def gen_version_manifest_upstream():
    """
    Generate version manifest for upstream Linux kernel source code.
    """
    base_url = "https://mirrors.edge.kernel.org/pub/linux/kernel"
    version_manifest = dict()
    r = requests.get(base_url)
    # get major version list via regex
    major_versions = sorted(
        list(set(re.findall(r'<a href="(v\d{1,2}\..)/">', r.text, flags=re.MULTILINE)))
    )
    major_versions.remove("v3.0")  # duplicate
    for major_version in tqdm(major_versions, ncols=60, bar_format=TQDM_BAR_FORMAT):
        r = requests.get(f"{base_url}/{major_version}")
        # get full version list via regex
        version_manifest[major_version] = sorted(
            list(
                set(
                    re.findall(
                        r'<a href="linux-(.*?).tar.gz">', r.text, flags=re.MULTILINE
                    )
                )
            )
        )
    with open(SC_DESC_FILE, "w") as f:
        yaml.dump(version_manifest, f, default_flow_style=False)
    logger.info("Generated version manifest for upstream Linux kernel source code")


def download_kernel_source_code(version, path):
    """
    Download Linux kernel source code for a specific version.
    """
    logger.debug(f"Downloading {version} kernel source code")
    # get middle dir from SC_DESC_FILE
    with open(SC_DESC_FILE, "r") as f:
        version_manifest = yaml.safe_load(f)
    middle_dir = None
    for mid, versions in version_manifest.items():
        if version in versions:
            middle_dir = mid
            break
    if middle_dir is None:
        logger.warning(f"Version {version} not found in version manifest")
        middle_dir = "v" + version.split(".")[0] + ".x"
    filename = "linux-" + version + ".tar.gz"
    url = f"{KERNEL_SOURCE_CODE_BASE_URL}/{middle_dir}/{filename}"
    status = download_file(url, f"{path}/{filename}")
    if status:
        logger.debug("Decompressing kernel source code")
        # decompress source code into 'kernel' dir
        with tarfile.open(f"{path}/{filename}", "r:gz") as tar:
            tar.extractall(path=path)
        os.rename(f"{path}/linux-{version}", f"{path}/{ENV_KERNEL_SUBDIR}")
        # delete tar.gz file
        os.remove(f"{path}/{filename}")
    else:
        logger.error(f"Failed to download kernel source code for {version}")
        sys.exit(-1)


def validate_kernel_version(version):
    """
    Check whether the given version is in version manifest.
    """
    # load version manifest
    version_manifest = load_version_manifest()
    if version not in version_manifest:
        return False
    return True


def get_next_version(version):
    """
    Get next version of a given version.
    """
    # load version manifest
    version_manifest = load_version_manifest()
    try:
        idx = version_manifest.index(version)
        if idx == len(version_manifest) - 1:
            return version
        return version_manifest[idx + 1]
    except IndexError:
        logger.warning("Failed to index {version} in version manifest")
        return version


def get_prev_version(version):
    """
    Get previous version of a given version.
    """
    # load version manifest
    version_manifest = load_version_manifest()
    try:
        idx = version_manifest.index(version)
        if idx == 0:
            return version
        return version_manifest[version_manifest.index(version) - 1]
    except IndexError:
        logger.warning("Failed to index {version} in version manifest")
        return version


def get_file_raw_text(path, version):
    """
    Get file raw text from kernel.org.
    """
    url = KERNEL_OFFICIAL_FILE_URL_TMPL.format(path=path, version=version)
    r = requests.get(url)
    if r.status_code // 100 != 2:
        return None
    return r.text


def get_patch_raw_text(commit):
    """
    Get patch raw text given a commit hash.
    """
    url = f"{KERNEL_OFFICIAL_PATCH_BASE_URL}{commit}"
    r = requests.get(url)
    if r.status_code // 100 != 2:
        return None
    return r.text


def find_affected_files_in_patch(patch):
    """
    Find all the files affected by a patch.
    """
    file_changes = re.findall(r"diff --git a/(.*?) b/(.*?)\n", patch)
    affect_files = list()
    for change in file_changes:
        affect_files.append(change[0])
    return affect_files


def find_affected_funcs_in_patch(patch):
    """
    Find all the functions affected by a patch.
    """
    func_changes = re.findall(r"@@ -\d+,\d+ \+\d+,\d+ @@ (.*?)\n", patch)
    affect_funcs = set()
    for change in func_changes:
        affect_funcs.add(change.split("(")[0])
    return affect_funcs


def get_patch_raw_text_for_file(commit, file_rel_path):
    """
    Get patch raw text for a specific file given a commit hash.
    """
    url = KERNEL_OFFICIAL_PATCH_FOR_FILE_URL_TMPL.format(
        path=file_rel_path, commit=commit
    )
    r = requests.get(url)
    if r.status_code // 100 != 2:
        return None
    return r.text


def get_kconfig_list(kernel_dir):
    """
    Get Kconfig file list in a kernel source code directory.
    """
    kconfig_files = list()
    # check if kernel_dir is a directory
    if not os.path.isdir(kernel_dir):
        logger.error(f"{kernel_dir} is not a directory")
        return kconfig_files
    for root, dirs, files in os.walk(kernel_dir):
        for file in files:
            if file == "Kconfig" or file == "Kconfig.debug":
                kconfig_files.append(os.path.join(root, file))
    return kconfig_files


def is_kconfig_expression(expr):
    """
    Check if a string is a Kconfig expression (not a single entry).
    """
    # check if the expr contains only [a-z], [A-Z] and _ with regex
    if re.fullmatch(r"^[a-zA-Z0-9_]+$", expr):
        return False
    return True


def is_AND_expr(expr):
    """
    Check if a string is like "expr_A && expr_B" and both expr_A and expr_B are single entry.
    """
    if "&&" not in expr:
        return False
    sub_exprs = expr.split("&&")
    for sub_expr in sub_exprs:
        if is_kconfig_expression(sub_expr.strip()):
            return False
    return True


def get_sub_kconfig_file_path(cur_abs, sub_kcfg):
    """
    Get absolute path of a sub Kconfig file.
    """
    res = (
        f"{PROJECT_DIR}"
        + f"/{'/'.join(get_pjt_rel_path(cur_abs).split('/')[0:4])}"
        + "/{sub_kcfg}".format(sub_kcfg=sub_kcfg)
    )
    return re.sub(r"/{2,}", "/", res)


def parse_kconfig_node_attr(G, node, string):
    """
    Parse Kconfig node attributes from a string.
    """
    if string.startswith("\t\t"):
        string = string[1:]
    if string.startswith("\tbool"):
        G.nodes[node]["type"] = KCFG_GRAPH_NODE_TYPE_BOOL
    if string.startswith("\ttristate"):
        G.nodes[node]["type"] = KCFG_GRAPH_NODE_TYPE_TRISTATE
    if string.startswith("\tstring"):
        G.nodes[node]["type"] = KCFG_GRAPH_NODE_TYPE_STRING
    if string.startswith("\tint"):
        G.nodes[node]["type"] = KCFG_GRAPH_NODE_TYPE_INT
    if string.startswith("\thex"):
        G.nodes[node]["type"] = KCFG_GRAPH_NODE_TYPE_HEX
    if string.startswith("\tdef"):
        # TODO: deal with expression
        # e.g., def_bool NETFILTER_EGRESS && (NET_CLS_ACT || IFB)
        # deal with multi defaults
        G.nodes[node]["default"] = string.strip().split()[1]


def add_kconfig_nodes(G, kcfg_file, arch):
    """
    Add Kconfig nodes to a graph.
    """
    try:
        with open(kcfg_file, "r") as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError) as e:
        logger.error(f"Failed to open {kcfg_file}")
        return
    cur_cfg = None
    for line in lines:
        if line.startswith("source "):
            sub_kcfg = line.strip().split()[1].strip("\"'")
            if "$(SRCARCH)" in sub_kcfg:
                sub_kcfg = sub_kcfg.replace("$(SRCARCH)", arch)
            if "$SRCARCH" in sub_kcfg:
                sub_kcfg = sub_kcfg.replace("$SRCARCH", arch)
            add_kconfig_nodes(
                G,
                get_sub_kconfig_file_path(cur_abs=kcfg_file, sub_kcfg=sub_kcfg),
                arch=arch,
            )
            continue
        # deal with config and menuconfig
        if (
            line.startswith("config ")
            or line.startswith("menuconfig ")
            or line.startswith("\tconfig ")
        ):
            cur_cfg = line.strip().split()[1]
            G.add_node(
                cur_cfg,
                category=KCFG_GRAPH_NODE_CATEGORY_CONFIG
                if line.strip().startswith("config ")
                else KCFG_GRAPH_NODE_CATEGORY_MENUCONFIG,
            )
            # remove "workdir/envs/ENV_ID/kernel
            G.nodes[cur_cfg]["file"] = "/".join(
                get_pjt_rel_path(kcfg_file).split("/")[4:]
            )
            continue
        # deal with menu virtual node (e.g., menu "I2C GPIO expanders")
        if line.startswith("menu "): 
            cur_cfg = line.strip().split("menu ")[1]
            G.add_node(
                cur_cfg,
                category=KCFG_GRAPH_NODE_CATEGORY_MENU,
            )
            G.nodes[cur_cfg]["type"] = KCFG_GRAPH_NODE_TYPE_VIRTUAL
            # remove "workdir/envs/ENV_ID/kernel
            G.nodes[cur_cfg]["file"] = "/".join(
                get_pjt_rel_path(kcfg_file).split("/")[4:]
            )
            continue
        if not cur_cfg:
            continue
        # deal with node attributes
        parse_kconfig_node_attr(G, cur_cfg, line)


def parse_kconfig_edge(G, node, string, in_choice_block=False):
    """
    Parse Kconfig edge type from a string.
    """
    if in_choice_block and string.startswith("\t\t"):
        string = string[1:]
        in_choice_block = False

    if string.startswith("\tbool ") and not in_choice_block:
        # deal with string like, bool "Enable 16-bit UID system calls" if EXPERT
        # we need to parse the `if EXPERT` part as KCFG_GRAPH_EDGE_TYPE_BOOL_IF_DEPEND edge
        if "if " in string:
            end_node = string.strip().split("if ")[-1]
            if is_kconfig_expression(end_node):
                # TODO: deal with expression later
                pass
            else:
                G.add_edge(node, end_node, type=KCFG_GRAPH_EDGE_TYPE_BOOL_IF_DEPEND)

    if string.startswith("\tdepends on ") and not in_choice_block:
        end_node = string.strip().split("depends on ")[-1]
        if is_kconfig_expression(end_node):
            if is_AND_expr(end_node):
                sub_exprs = end_node.split(" && ")
                for sub_expr in sub_exprs:
                    G.add_edge(
                        node, sub_expr.strip(), type=KCFG_GRAPH_EDGE_TYPE_DEPEND
                    )
            # TODO: deal with more complex expressions later
            pass
        else:
            G.add_edge(node, end_node, type=KCFG_GRAPH_EDGE_TYPE_DEPEND)
    if string.startswith("\tselect ") and not in_choice_block:
        end_node = string.strip().split("select ")[-1]
        if is_kconfig_expression(end_node):
            # TODO: deal with expression later
            pass
        else:
            G.add_edge(node, end_node, type=KCFG_GRAPH_EDGE_TYPE_SELECT)
    if string.startswith("\timply ") and not in_choice_block:
        end_node = string.strip().split("imply ")[-1]
        if is_kconfig_expression(end_node):
            # TODO: deal with expression later
            pass
        else:
            G.add_edge(node, end_node, type=KCFG_GRAPH_EDGE_TYPE_IMPLY)


def add_kconfig_edges(G, kcfg_file, arch, if_depend_stack=list(), menu_depend_stack = list()):
    """
    Add Kconfig edges to a graph.
    """
    try:
        with open(kcfg_file, "r") as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError) as e:
        logger.error(f"Failed to open {kcfg_file}")
        return
    # deal with 'depends on', 'select', 'imply', 'if', 'choice'
    cur_cfg = None
    in_choice_block = False
    # TODO: deal with 'choice' (currently on parse in-block config of choice)
    #       we haven't deal with choice_dep yet
    choice_dep = None  # TODO
    for line in lines:
        # deal with menu
        if line.startswith("menu "):
            cur_cfg = line.strip().split("menu ")[1]
            if menu_depend_stack:
                G.add_edge(
                    cur_cfg,
                    menu_depend_stack[-1],
                    type=KCFG_GRAPH_EDGE_TYPE_MENU_DEPEND,
                )
            menu_depend_stack.append(line.strip().split("menu ")[1])
            in_choice_block = False  # also end choice block
            continue
        # deal with if CONFIG
        if line.startswith("if "):
            rest = line.strip().split("if ")[-1]
            if is_kconfig_expression(rest):
                if is_AND_expr(rest):
                    sub_exprs = rest.split("&&")
                    if if_depend_stack:
                        for sub_expr in sub_exprs:
                            stack_sub_exprs = if_depend_stack[-1].split("&&")
                            for stack_sub_expr in stack_sub_exprs:
                                G.add_edge(
                                    sub_expr.strip(),
                                    stack_sub_expr.strip(),
                                    type=KCFG_GRAPH_EDGE_TYPE_IF_DEPEND,
                                )
                    if_depend_stack.append(rest)
                # TODO: deal with more complex expressions later
                pass
            else:
                # deal with "if CONFIG_A ... if CONFIG_B ... endif ... endif"
                if if_depend_stack:
                    sub_exprs = if_depend_stack[-1].split("&&")
                    for sub_expr in sub_exprs:
                        G.add_edge(
                            rest, sub_expr.strip(), type=KCFG_GRAPH_EDGE_TYPE_IF_DEPEND
                        )
                if_depend_stack.append(rest)
            continue
        if line.startswith("endif"):
            if if_depend_stack:
                if_depend_stack.pop()
            continue
        if line.startswith("endmenu"):
            if menu_depend_stack:
                menu_depend_stack.pop()
            continue
        # recursively add nodes and edges
        if line.startswith("source "):
            sub_kcfg = line.strip().split()[1].strip("\"'")
            if "$(SRCARCH)" in sub_kcfg:
                sub_kcfg = sub_kcfg.replace("$(SRCARCH)", arch)
            if "$SRCARCH" in sub_kcfg:
                sub_kcfg = sub_kcfg.replace("$SRCARCH", arch)

            add_kconfig_edges(
                G,
                get_sub_kconfig_file_path(cur_abs=kcfg_file, sub_kcfg=sub_kcfg),
                arch,
                if_depend_stack.copy(),
                menu_depend_stack.copy(),
            )
        if line.startswith("choice"):
            in_choice_block = True
            continue
        if (not line.startswith("\t")) or line.startswith("endchoice"):
            in_choice_block = False
        # deal with config and menuconfig
        if line.startswith("config ") or line.startswith("menuconfig "):
            cur_cfg = line.strip().split()[1]
            if if_depend_stack:
                top_if_depend = if_depend_stack[-1]
                if is_kconfig_expression(top_if_depend):
                    # deal with &&
                    if is_AND_expr(top_if_depend):
                        sub_exprs = top_if_depend.split("&&")
                        for sub_expr in sub_exprs:
                            G.add_edge(
                                cur_cfg, sub_expr.strip(), type=KCFG_GRAPH_EDGE_TYPE_IF_DEPEND
                            )
                    else:
                        pass
                else:
                    G.add_edge(
                        cur_cfg, top_if_depend, type=KCFG_GRAPH_EDGE_TYPE_IF_DEPEND
                    )
            if menu_depend_stack:
                top_menu_depend = menu_depend_stack[-1]
                G.add_edge(
                    cur_cfg, top_menu_depend, type=KCFG_GRAPH_EDGE_TYPE_MENU_DEPEND
                )
            in_choice_block = False  # also end choice block
            continue
        # deal with \t\tconfig
        if line.startswith("\t\tconfig "):
            cur_cfg = line.strip().split()[1]
        if not cur_cfg:
            continue
        parse_kconfig_edge(G, cur_cfg, line, in_choice_block)


def build_kcfg_graph(kernel_dir, arch):
    """
    Build a Kconfig graph for a kernel source code directory.
    """
    # kcfg_files = get_kconfig_list(kernel_dir)
    # if not kcfg_files:
    #     logger.error(f"Failed to find Kconfig files")
    #     return None
    G = nx.DiGraph()
    # add nodes
    add_kconfig_nodes(G, f"{kernel_dir}/Kconfig", arch=arch)
    # add edges
    add_kconfig_edges(G, f"{kernel_dir}/Kconfig", arch=arch)
    logger.info(f"Built kcfg graph ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)")
    return G


def get_file_configs_from_kbuild(target, kernel_dir, file_rel_path, kbuild_filename):
    """
    Get kernel configs for a single file in Kbuild.
    """
    res = set()
    kbuild_file = f"{kernel_dir}/{'/'.join(file_rel_path)}/{kbuild_filename}"
    if not os.path.isfile(kbuild_file):
        return res
    with open(kbuild_file, "r") as f:
        lines = f.readlines()
    for line in lines:
        # use regex to find obj-$(CONFIG_XXX) += target (should handle whitespaces and tabs)
        match = re.search(
            r"obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+=\s*{target}".format(target=target),
            line,
        )
        if match:
            res.add(match.group(1))
            break
    return res


def get_file_configs(kernel_dir, file_rel_path):
    """
    Get kernel config for a single file in Makefiles.
    """
    # e.g., for file_rel_path="net/ipv4/netfilter/arp_tables.c"
    # we need to find config in "net/ipv4/netfilter/Makefile" for "arp_tables.o"
    # the related line is: obj-$(CONFIG_IP_NF_ARPTABLES) += arp_tables.o
    #   so we get CONFIG_IP_NF_ARPTABLES
    # then we need to find config in "net/ipv4/Makefile" for "netfilter/"
    # the related line is: obj-$(CONFIG_NETFILTER) += netfilter.o netfilter/
    #   so we get CONFIG_NETFILTER
    # then we need to find config in "net/Makefile" for "ipv4/"
    # the related line is: obj-$(CONFIG_INET)      += ipv4/
    #   so we get CONFIG_INET
    # then we need to find config in "Makefile" for "net/"
    # the related line is: obj-y += net/ virt/
    #   so we get nothing for "net/"
    # done
    res = set()
    if not file_rel_path.endswith(".c"):
        # logger.warning(f"Skip non-c file {file_rel_path}")
        return res

    path_entries = file_rel_path.split("/")
    path_entries[-1] = path_entries[-1].replace(".c", ".o")
    entry_cnt = len(path_entries)
    # add '/' for each entry except the last one
    for i in range(entry_cnt - 1):
        path_entries[i] += "/"
    for i in range(entry_cnt):
        target = path_entries[entry_cnt - (i + 1)]
        res.update(get_file_configs_from_kbuild(target, kernel_dir, path_entries[0:entry_cnt-(i+1)], "Kbuild"))
        res.update(get_file_configs_from_kbuild(target, kernel_dir, path_entries[0:entry_cnt-(i+1)], "Makefile"))
    return res


def get_func_configs(kernel_dir, file_rel_path, func_probe):
    """
    Get kernel configs before and within a single function.
    """
    res = set()
    try:
        with open(f"{kernel_dir}/{file_rel_path}", "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return res
    # find the line number of the function tail '}'
    func_tail_line = None
    probe_line = None
    for i in range(len(lines)):
        if lines[i].startswith(func_probe):
            probe_line = i
        if probe_line != None and lines[i].strip() in ["}", "};"]:
            func_tail_line = i
            break
    if probe_line == None or func_tail_line == None:
        return res
    # search for CONFIG_XXX before func
    ifdef_stack = list()
    for i in range(probe_line):
        line = lines[i].strip()
        # deal with ifdef
        if line.startswith("#ifdef"):
            ifdef_stack.append(line.strip().split()[1])
            continue
        if line.startswith("#endif"):
            if ifdef_stack:
                ifdef_stack.pop()
            continue
    if ifdef_stack:
        res.update(set(ifdef_stack))
    # search for CONFIG_XXX within func
    for i in range(probe_line, func_tail_line + 1):
        line = lines[i].strip()
        if line.startswith("#ifdef"):
            res.add(line.strip().split()[1])
            continue

    return res


def get_code_configs(kernel_dir, file_rel_path, commit):
    """
    Get kernel configs within a single file.
    """
    res = set()
    commit_raw = get_patch_raw_text_for_file(commit=commit, file_rel_path=file_rel_path)
    if commit_raw is None:
        return res
    affected_funcs = find_affected_funcs_in_patch(commit_raw)
    for affected_func in affected_funcs:
        res.update(get_func_configs(kernel_dir, file_rel_path, affected_func))
    return res


def get_arch_path_mappings(arch="x86"):
    try:
        return SC_PATH_MAPPINGS[arch]
    except KeyError:
        return None
