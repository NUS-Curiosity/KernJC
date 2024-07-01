"""
This file provides functions to manage vulnerability information.
"""

import requests
import tempfile
import re
import time
import sys
import packaging.version as ver
import yaml
import networkx as nx
from bs4 import BeautifulSoup
from tqdm import tqdm

import src.env_manager as env_manager
from src.global_vars import *
from src.logger_config import configure_logger
import src.sc_manager as sc_manager
from src.util import (
    ensure_dir,
    contain_str,
    save_file,
    run_cmd_get_stdout,
    get_cpu_vendor,
)

logger = configure_logger("vuln_manager")

vuln_range_funcs = {
    2: lambda version, range_start, range_end: ver.parse(range_start)
    <= ver.parse(version)
    <= ver.parse(range_end),
    3: lambda version, range_start, range_end: ver.parse(range_start)
    < ver.parse(version)
    <= ver.parse(range_end),
    4: lambda version, range_start, range_end: ver.parse(range_start)
    <= ver.parse(version)
    < ver.parse(range_end),
    5: lambda version, range_start, range_end: ver.parse(range_start)
    < ver.parse(version)
    < ver.parse(range_end),
}


def get_local_cve_record(cve):
    """
    Get local CVE record.
    """
    try:
        with open(f"{VULN_DESC_DIR}/{cve.split('-')[1]}/{cve}.yaml", "r") as f:
            vuln_desc = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Vuln desc for {cve} does not exist")
        return None
    return vuln_desc


def get_vuln_version_list(cve, vuln_ranges):
    """
    Given a list of [versionStart, versionEnd, lambda func],
    get vulnerable version list from version manifest.
    """
    # load version manifest
    version_manifest = sc_manager.load_version_manifest()
    vuln_version_list = list()
    for vuln_range in vuln_ranges:
        if vuln_range[2] == 0 or vuln_range[2] == 1:
            # logger.warning("skip vuln range which only has start bound")
            continue
        for version in version_manifest:
            try:
                if vuln_range_funcs[vuln_range[2]](
                    version, vuln_range[0], vuln_range[1]
                ):
                    vuln_version_list.append(str(version))
            except ver.InvalidVersion:
                continue

    # check and filter FP versions at the end of the list via patch
    for i in range(len(vuln_version_list) - 1, -1, -1):
        fp = False
        res = check_version_vuln_using_patch(cve, vuln_version_list[i], verbose=False)
        for _, status in res.items():
            if PATCH_STATUS_PATCHED in status:
                fp = True
                break
        if fp:
            continue
        else:
            break
    try:
        return vuln_version_list[: i + 1]
    except UnboundLocalError:
        return list()


def _get_cve_list_from_linux_kernel_cves():
    """
    Get Linux Kernel CVE list from GitHub repo: https://github.com/nluedtke/linux_kernel_cves.
    """
    logger.debug("Getting latest CVE list from GitHub repo (linux_kernel_cves)")
    url = "https://raw.githubusercontent.com/nluedtke/linux_kernel_cves/master/data/CVEs.txt"
    r = requests.get(url)
    if r.status_code // 100 != 2:
        logger.error(
            f"Failed to get CVE list from GitHub repo (linux_kernel_cves). Status code: {r.status_code}"
        )
        sys.exit(1)
    temp = r.text.split("\n")
    # using regex to extract CVE lines (extracting only CVE IDs)
    cves = sorted(
        [line.split(":")[0] for line in temp if re.match(r"^CVE-\d{4}-\d{4,7}", line)]
    )

    logger.info(f"Got {len(cves)} CVEs from GitHub repo (linux_kernel_cves)")

    return cves


def _get_cve_list_from_linux_cve_announce():
    """
    Get Linux Kernel CVE list from linux-cve-announce repo: https://git.kernel.org/pub/scm/linux/security/vulns.git.
    """
    cves = set()
    logger.debug("Getting latest CVE list from linux-cve-announce repo")
    current_year = int(time.strftime("%Y", time.localtime()))
    # linux-cve-announce
    url = "https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/published"
    # get all the cve ID from the repo
    for year in range(2019, current_year + 1):
        r = requests.get(f"{url}/{year}")
        if r.status_code // 100 != 2:
            logger.error(
                f"Failed to get CVE list from linux-cve-announce repo for {year}"
            )
            continue
        time.sleep(0.5)
        # find all CVE IDs with regex in r.text
        cves.update(re.findall(CVE_PATTERN, r.text))
    
    # sort
    cves = sorted(list(cves))

    logger.info(f"Got {len(cves)} CVEs from linux-cve-announce repo")

    return cves


def get_cve_list():
    return _get_cve_list_from_linux_cve_announce()


def get_cve_info_from_nvd(cve, api_key):
    """
    Get CVE info from NVD using NVD API.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "apiKey": api_key,
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
    r = requests.get(url, headers=headers)
    # if status is 2xx, then the request was successful
    if r.status_code // 100 == 2:
        # if there is no such a CVE in NVD, then return None
        res = r.json()["vulnerabilities"]
        if res:
            return res[0]["cve"]

    return None


def get_cve_info_from_nvd_in_batch(cves, api_key):
    """
    Get CVE info from NVD using NVD API in batch with rolling.
    """
    if len(cves) == 0:
        return
    logger.debug(f"Getting CVE info from NVD for {len(cves)} CVEs in batch")
    res = list()
    start_time = time.time()
    cnt = 0
    for cve in tqdm(cves, ncols=60, bar_format=TQDM_BAR_FORMAT):
        info = get_cve_info_from_nvd(cve, api_key)
        if info is not None:
            ensure_dir(f"{VULN_DESC_DIR}/{cve.split('-')[1]}")
            fw = open(f"{VULN_DESC_DIR}/{cve.split('-')[1]}/{cve}.yaml", "w")
            yaml.dump(info, fw)
            fw.close()
            res.append(cve)
            cnt += 1
        if cnt != 0 and cnt % NVD_REQUEST_ROLLING_LIMIT == 0:
            # elapsed_time = time.time() - start_time
            # if elapsed_time < NVD_REQUEST_ROLLING_TIME_WINDOW:
            #    time.sleep(NVD_REQUEST_ROLLING_TIME_WINDOW - elapsed_time)
            #    start_time = time.time()
            time.sleep(2)

    logger.info(f"{cnt}/{len(cves)} CVEs are stored in {VULN_DESC_DIR}")


def diff_cve_list(new_list):
    """
    Compare new CVE list with old CVE list and return the difference.
    """
    # load old CVE list from items.yaml
    with open(VULN_DESC_FILE, "r") as f:
        old = yaml.safe_load(f)
    if old:
        old_list = [item["cve"] for item in old]
        # check the cve file, if the vulnStatus is 'Awaiting Analysis', then remove it
        for item in old:
            if (vuln_desc := get_local_cve_record(item["cve"])) is not None:
                if vuln_desc.get("vulnStatus") == "Awaiting Analysis":
                    old_list.remove(item["cve"])
    else:
        old_list = list()
    return sorted(list(set(new_list) - set(old_list)))


def get_vuln_ranges(cve):
    """
    Get vulnerable version ranges from local vuln desc.
    """
    if (vuln_desc := get_local_cve_record(cve)) is None:
        return None

    # get vulnerable version ranges
    vuln_ranges = list()
    try:
        for configuration in vuln_desc["configurations"]:
            for node in configuration["nodes"]:
                cpe_match = node["cpeMatch"]
                for match in cpe_match:
                    if match["vulnerable"] and match["criteria"].startswith(
                        LINUX_KERNEL_CPE
                    ):
                        vuln_range = [VER_MIN, VER_MAX, 0]
                        if match.get("versionStartIncluding"):
                            # if not sc_manager.validate_kernel_version(
                            #     match["versionStartIncluding"]
                            # ):
                            #     continue
                            vuln_range[0] = match["versionStartIncluding"]
                            vuln_range[2] += RANGE_START_IN_WEIGHT  # 0
                        if match.get("versionStartExcluding"):
                            # if not sc_manager.validate_kernel_version(
                            #     match["versionStartExcluding"]
                            # ):
                            # continue
                            vuln_range[0] = match["versionStartExcluding"]
                            vuln_range[2] += RANGE_START_EX_WEIGHT  # 1
                        if match.get("versionEndIncluding"):
                            # if not sc_manager.validate_kernel_version(
                            #     match["versionEndIncluding"]
                            # ):
                            #     continue
                            vuln_range[1] = match["versionEndIncluding"]
                            vuln_range[2] += RANGE_END_IN_WEIGHT  # 2
                        if match.get("versionEndExcluding"):
                            # if not sc_manager.validate_kernel_version(
                            #     match["versionEndExcluding"]
                            # ):
                            #     continue
                            vuln_range[1] = match["versionEndExcluding"]
                            vuln_range[2] += RANGE_END_EX_WEIGHT  # 4
                        if vuln_range[0] != VER_MIN or vuln_range[1] != VER_MAX:
                            vuln_ranges.append(vuln_range)
    except KeyError:
        pass
    return vuln_ranges


def _find_patch_href_via_needle(needle, web_page):
    """
    Find patch href(s) in a web page, given a preceding needle.
    """
    soup = BeautifulSoup(web_page, "html.parser")
    try:
        res = soup.find_all(string=lambda s: contain_str(needle, s))
    except AttributeError:
        return None

    return res


def _get_patch_commit_hash_via_ubuntu_security(cve):
    """
    Get patch commit hash via Ubuntu Security.
    """
    url = f"https://ubuntu.com/security/{cve}"
    r = requests.get(url)
    if r.status_code // 100 != 2:
        return None
    fixed = _find_patch_href_via_needle(needle="Fixed by", web_page=r.text)
    if not fixed:
        return None
    commits = set()
    for entry in fixed:
        commit = entry.find_next("a")
        if commit and commit.attrs["href"].startswith(KERNEL_OFFICIAL_GIT_BASE_URL):
            # check if the commit hash is valid and strip the unnecessary suffix
            # e.g., for CVE-2021-22555, which has invalid string on the page:
            # 722d94847de29310e8aa03fcbdb41fc92c521756|local-CVE-2022-0185-fix
            match = re.findall(r"([a-f0-9]{20,40})", commit.text)
            if match:
                commits.add(match[0])
    return list(commits)


def _get_patch_commit_hash_via_redhat_bugzilla(cve):
    """
    Get patch commit hash via Red Hat Bugzilla.
    """
    url = f"https://bugzilla.redhat.com/show_bug.cgi?id={cve}"
    r = requests.get(url)
    if r.status_code // 100 != 2:
        return None
    # acutally, Red Hat Bugzilla always returns 200, so we need to check the content
    if "is not a valid bug number nor an alias to a bug." in r.text:
        return None
    fixed = _find_patch_href_via_needle(needle="Upstream patch", web_page=r.text)
    # TODO: sometimes, Red Hat Bugzilla just list the patches following 'References',
    #      if we want to leverage this info, we must visit the link to determine
    #      whether it is the patch commit link or the bug introduction link.
    if not fixed:
        return None
    commits = set()
    for entry in fixed:
        commit = entry.find_next("a")
        while commit and commit.attrs["href"].startswith(KERNEL_OFFICIAL_GIT_BASE_URL):
            match = re.search(r"id=([a-f0-9]{5,40})", commit.text)
            if match:
                commits.add(match.group(1))
            commit = commit.find_next("a")
    return list(commits)


def _get_patch_commit_hash_via_suse_bugzilla(cve):
    """
    Get patch commit hash via SUSE Bugzilla.
    """
    pass


def _get_patch_commit_hash_via_nvd(cve):
    """
    Get patch commit hash via NVD.
    """
    # try:
    #     with open(VULN_DESC_DIR + f"/{cve.split('-')[1]}/{cve}.yaml", "r") as f:
    #         vuln_desc = yaml.safe_load(f)
    # except FileNotFoundError:
    #     logger.error(f"Vuln desc for {cve} does not exist")
    #     return None
    commits = set()
    return list(commits)


def get_patch_commit_hash(cve):
    """
    Get patch commit hash in some approaches.
    """
    commits = None
    # NVD sometimes provides incorrect info, e.g. for CVE-2021-22555, it provides
    # two links with 'Patch' tag, while one of them is the vuln introduction link.
    # So we try other approaches before using NVD info.

    # step 1: try with Ubuntu Security (https://ubuntu.com/security)
    # BTW, Ubuntu also provides introduction commit link.
    # Shall we fetch it as well? What can we do with it? #TODO
    commits = _get_patch_commit_hash_via_ubuntu_security(cve)
    if commits:
        return commits

    # step 2: try with Red Hat Bugzilla (https://bugzilla.redhat.com)
    commits = _get_patch_commit_hash_via_redhat_bugzilla(cve)
    if commits:
        return commits

    # skip step 3, as the info on SUSE Bugzilla is hard to extract
    # step 3: try with SUSE Bugzilla (https://bugzilla.suse.com)
    # commits = _get_patch_commit_hash_via_suse_bugzilla(cve)
    # if commits:
    #     return commits

    # step 4: try with NVD reference link
    commits = _get_patch_commit_hash_via_nvd(cve)

    return commits


def gen_cve_manifest():
    """
    Generate CVE manifest file for all downloaded CVE info.
    """
    logger.debug("Generating CVE manifest file (with patch commit hash)")
    cves = list()
    existing_cves = dict()
    # load existing CVE manifest file
    try:
        with open(VULN_DESC_FILE, "r") as f:
            existing_cves_data = yaml.safe_load(f)
            if existing_cves_data:
                existing_cves = {
                    item["cve"]: item["patch"] for item in existing_cves_data
                }
    except FileNotFoundError:
        pass

    # get the whole CVE list
    all_cves = list()
    for year in os.listdir(VULN_DESC_DIR):
        if not re.match(r"^\d{4}$", year):
            continue
        for cve in os.listdir(VULN_DESC_DIR + f"/{year}"):
            all_cves.append(cve.split(".")[0])

    current_year = time.strftime("%Y", time.localtime())

    with open(VULN_DESC_FILE, "w") as f:
        for cve in tqdm(
            all_cves,
            ncols=60,
            bar_format=TQDM_BAR_FORMAT,
        ):
            cve_id = cve.split(".")[0]
            # if the CVE is not in the existing CVE manifest file,
            # or the CVE is in the existing CVE manifest file but the patch is empty,
            # then we try to get the patch commit hash
            if cve_id not in existing_cves or (
                existing_cves.get(cve_id) == []
                and cve_id.startswith(f"CVE-{current_year}-")
            ):
                patch = get_patch_commit_hash(cve_id)
                time.sleep(0.7)
            # otherwise, we use the patch commit hash in the existing CVE manifest file
            else:
                patch = existing_cves[cve_id]
            cves.append({"cve": cve_id, "patch": patch})
        cves.sort(key=lambda x: x["cve"])
        yaml.dump(cves, f)

    logger.info(f"Generated CVE manifest file")


def get_cve_patch(cve):
    """
    Get patch commits for a CVE.
    """
    patch = None
    with open(VULN_DESC_FILE, "r") as f:
        cves = yaml.safe_load(f)
        for item in cves:
            if item["cve"] == cve:
                patch = [commit for commit in item["patch"]]
                break
    return patch


def get_cve_info(cve):
    """
    Query a CVE.
    """
    if (vuln_desc := get_local_cve_record(cve)) is None:
        return None
    description = None
    for desc in vuln_desc["descriptions"]:
        if desc["lang"] == "en":
            description = desc["value"]
            break

    # get patch commits if any
    patch = get_cve_patch(cve)
    if patch is not None:
        patch = [f"{KERNEL_OFFICIAL_COMMIT_BASE_URL}{commit}" for commit in patch]
    else:
        patch = list()
    # get vulnerable range
    vuln_ranges = get_vuln_ranges(cve)

    # recommendation for reproduction
    vuln_versions = get_vuln_version_list(cve, vuln_ranges)[-3:]

    return {
        "cve": cve,
        "description": description,
        "patch": patch,
        "vuln_ranges": [vuln_range[0:2] for vuln_range in vuln_ranges],
        "vuln_version_candidates": vuln_versions,
    }


def get_cve_candidate_kernel_version(cve):
    """
    Get candidate kernel versions for a CVE.
    """
    vuln_ranges = get_vuln_ranges(cve)
    if not vuln_ranges:
        return None
    candidates = get_vuln_version_list(cve, vuln_ranges)
    if len(candidates) > 0:
        return candidates[-1]
    else:
        return None


def check_version_vuln_using_patch(cve, kernel_version, verbose=True):
    """
    Check if a kernel version is vulnerable to a CVE based on patch.
    """
    patch = get_cve_patch(cve)
    if verbose:
        logger.debug(f"Checking {cve} aginst v{kernel_version} kernel using patch")
    res = dict()
    for commit in patch:
        only_code_addition = False
        res[commit] = set()
        # get the patch raw text
        patch_content = sc_manager.get_patch_raw_text(commit)
        if patch_content is None:
            if verbose:
                logger.warning(f"Failed to get patch {commit}")
            continue
        # TODO: it is hard to deal with only_code_addition case
        #       now let's just skip it
        if not re.search(r"^-[\s\t]+", patch_content, re.MULTILINE):
            only_code_addition = True
            continue
        # find all the files affected by the patch
        affect_files = sc_manager.find_affected_files_in_patch(patch_content)
        # logger.info(f"{len(affect_files)} file(s) affected by commit {commit}")

        # create a tmp dir to store the affected files and patch
        with tempfile.TemporaryDirectory() as tmp_dir:
            # logger.debug(f"Conducting patch checking in {tmp_dir}")
            for file in affect_files:
                # create the dir if not exist
                ensure_dir(f"{tmp_dir}/{os.path.dirname(file)}")
                # get the file raw text
                file_text = sc_manager.get_file_raw_text(file, kernel_version)
                if file_text is None:
                    if verbose:
                        logger.warning(f"Failed to get {file} from kernel.org")
                    continue
                # save the file raw text
                save_file(content=file_text, save_path=f"{tmp_dir}/{file}")
            # save the patch
            save_file(content=patch_content, save_path=f"{tmp_dir}/{cve}.patch")
            # try to apply the patch
            # NOTE: you should run this function on Linux,
            #       as the `patch` on Mac OS has different results
            cmd = f"cd {tmp_dir} && patch --dry-run -p1 --batch < {cve}.patch"
            # run with subprocess to get the result
            stdout = run_cmd_get_stdout(cmd)
            if "FAILED" in stdout or "can't find file to patch" in stdout:
                res[commit].add(PATCH_STATUS_FAIL)
            if "Reversed (or previously applied) patch detected" in stdout:
                res[commit].add(PATCH_STATUS_PATCHED)
            if not (
                "FAILED" in stdout
                or "patch detected" in stdout
                or "can't find file to patch" in stdout
            ):
                res[commit].add(PATCH_STATUS_SUCCESS)
            if only_code_addition:
                cmd = f"cd {tmp_dir} && patch --dry-run -p1 --batch --reverse < {cve}.patch"
                stdout = run_cmd_get_stdout(cmd)
                if "FAILED" in stdout or "can't find file to patch" in stdout:
                    res[commit].add(PATCH_STATUS_FAIL)
                if "Unreversed patch detected" in stdout:
                    res[commit].add(PATCH_STATUS_SUCCESS)
                if not (
                    "FAILED" in stdout
                    or "Unreversed patch detected" in stdout
                    or "can't find file to patch" in stdout
                ):
                    res[commit].add(PATCH_STATUS_PATCHED)
    return res


def check_version_vuln_using_range(cve, kernel_version):
    """
    Check if a kernel version is vulnerable to a CVE based on NVD range data.
    """
    logger.debug(f"Checking {cve} aginst v{kernel_version} kernel using NVD data")
    vuln_ranges = get_vuln_ranges(cve)
    if not vuln_ranges:
        logger.error(f"Vuln ranges for {cve} does not exist")
        return None
    candidates = get_vuln_version_list(cve, vuln_ranges)
    if kernel_version in candidates:
        return True

    return False


def get_cve_cfgs(cve, env_id, arch="x86", print_out=False):
    """
    Get CVE configs for a CVE.
    Note: We cannot ensure the kcfgs gotten from CVE info works for ExP or PoC.
          To get the kcfgs for PoC/ExP, we need to conduct kernel code analysis
          according to PoC/ExP code.
    """
    cfgs = set()
    logger.debug(
        f"Finding kernel configs for {cve} in env {env_manager.get_short_env_id(env_id)}"
    )
    env_dir = env_manager.get_env_dir(env_id)
    # build kernel config graph
    logger.debug(f"Building kcfg graph for env {env_manager.get_short_env_id(env_id)}")
    kcfg_graph = sc_manager.build_kcfg_graph(
        kernel_dir=f"{env_dir}/{ENV_KERNEL_SUBDIR}", arch=arch
    )

    # find CONFIG_* in vuln desc (if available)
    cve_info = get_cve_info(cve)
    desc_vuln_files = set()
    if cve_info:
        # use re to find all the CONFIG_* in the description
        match = re.findall(r"CONFIG_[A-Z0-9_]+", cve_info["description"])
        if match:
            cfgs.update(match)
        if print_out:
            logger.info(f"[CONFIG] DC for {cve}: {[item[7:] for item in match]}")
        # find potential affected files in vuln desc (path/to/file.c): e.g., drivers/staging/irda/net/af_irda.c
        match = re.findall(r"[\w/]+\.c", cve_info["description"])
        if match:
            desc_vuln_files.update(match)

    patch = get_cve_patch(cve)
    if not patch:
        logger.warning(f"Cannot get patch commits for {cve}")
        return None
    # find all first-order configs
    file_configs = set()
    code_configs = set()
    for commit in patch:
        commit_raw = sc_manager.get_patch_raw_text(commit)
        if commit_raw is None:
            logger.warning(f"Failed to get patch {commit}")
            continue
        affected_files = sc_manager.find_affected_files_in_patch(commit_raw)
        affected_files.extend(list(desc_vuln_files))
        for affect_file in affected_files:
            file_configs.update(
                sc_manager.get_file_configs(
                    kernel_dir=f"{env_dir}/{ENV_KERNEL_SUBDIR}",
                    file_rel_path=affect_file,
                )
            )
            # check if we need to also consider files in the arch-specific dir
            arch_path_mappings = sc_manager.get_arch_path_mappings(arch)
            if arch_path_mappings:
                for key, value in arch_path_mappings.items():
                    if key in affect_file:
                        mapped_affect_file = affect_file.replace(key, value)
                        file_configs.update(
                            sc_manager.get_file_configs(
                                kernel_dir=f"{env_dir}/{ENV_KERNEL_SUBDIR}",
                                file_rel_path=mapped_affect_file,
                            )
                        )
                        break
            code_configs.update(
                sc_manager.get_code_configs(
                    kernel_dir=f"{env_dir}/{ENV_KERNEL_SUBDIR}",
                    file_rel_path=affect_file,
                    commit=commit,
                )
            )
    if print_out:
        logger.info(f"[CONFIG] FC for {cve}: {[item[7:] for item in file_configs]}")
        logger.info(f"[CONFIG] CC for {cve}: {[item[7:] for item in code_configs]}")
    cfgs.update(file_configs)
    cfgs.update(code_configs)
    # for vulns in kvm, the cfg for cpu vendor is also needed
    if "CONFIG_KVM" in cfgs:
        cpu_vendor = get_cpu_vendor()
        if cpu_vendor:
            cfgs.add(f"CONFIG_KVM_{cpu_vendor}")

    # remove 'CONFIG_' prefix
    cfgs = {cfg[7:] for cfg in cfgs}
    res = set()
    HRC = set()
    HSC = set()
    HDC = set()
    # find all hidden configs
    # find all the descendants of the cfgs
    for cfg in cfgs:
        try:
            HRC.update(nx.descendants(kcfg_graph, cfg))
        except nx.exception.NetworkXError:
            continue
    res.update(HRC)
    res.update(cfgs)
    # find all nodes which has edge of KCFG_GRAPH_EDGE_TYPE_SELECT type to the cfgs
    # e.g., CONFIG_BPF_SYSCALL selects CONFIG_BPF
    for cfg in cfgs:
        for node in kcfg_graph.nodes:
            # check if the node has edge of KCFG_GRAPH_EDGE_TYPE_SELECT type to the cfgs
            # the edge is added by code G.add_edge(node, end_node, type=KCFG_GRAPH_EDGE_TYPE_SELECT)
            if (
                kcfg_graph.has_edge(node, cfg)
                and kcfg_graph.edges[node, cfg]["type"] == KCFG_GRAPH_EDGE_TYPE_SELECT
            ):
                # res.update(nx.descendants(kcfg_graph, node))
                HSC.add(node)
            # check if the node has edge of KCFG_GRAPH_EDGE_TYPE_DEPEND type to the cfgs
            # the edge is added by code G.add_edge(node, end_node, type=KCFG_GRAPH_EDGE_TYPE_DEPEND)
            if (
                kcfg_graph.has_edge(node, cfg)
                and kcfg_graph.edges[node, cfg]["type"] == KCFG_GRAPH_EDGE_TYPE_DEPEND
                or kcfg_graph.has_edge(node, cfg)
                and kcfg_graph.edges[node, cfg]["type"]
                == KCFG_GRAPH_EDGE_TYPE_MENU_DEPEND
            ):
                try:
                    if kcfg_graph.nodes[node]["type"] == KCFG_GRAPH_NODE_TYPE_VIRTUAL:
                        for node2 in kcfg_graph:
                            if (
                                kcfg_graph.has_edge(node2, node)
                                and kcfg_graph.edges[node2, node]["type"]
                                == KCFG_GRAPH_EDGE_TYPE_DEPEND
                                or kcfg_graph.has_edge(node2, node)
                                and kcfg_graph.edges[node2, node]["type"]
                                == KCFG_GRAPH_EDGE_TYPE_MENU_DEPEND
                            ):
                                HDC.add(node2)
                    else:
                        HDC.add(node)
                except KeyError:
                    HDC.add(node)
    res.update(HSC)
    res.update(HDC)
    # remove all virtual nodes
    res_without_virtual = set()
    for cfg in res:
        try:
            if kcfg_graph.nodes[cfg]["type"] != KCFG_GRAPH_NODE_TYPE_VIRTUAL:
                res_without_virtual.add(cfg)
            else:
                if cfg in HRC:
                    HRC.remove(cfg)
                if cfg in HSC:
                    HSC.remove(cfg)
                if cfg in HDC:
                    HDC.remove(cfg)
        except KeyError:
            res_without_virtual.add(cfg)
    if print_out:
        logger.info(f"[CONFIG] HRC for {cve}: {HRC}")
        logger.info(f"[CONFIG] HSC for {cve}: {HSC}")
        logger.info(f"[CONFIG] HDC for {cve}: {HDC}")
    return list(res_without_virtual)
