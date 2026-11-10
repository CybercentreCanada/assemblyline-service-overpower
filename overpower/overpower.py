import json
import os
import re
import subprocess

from contextlib import chdir
from copy import deepcopy
from threading import Thread
from time import sleep, time
from typing import Any

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.forge import get_identify
from assemblyline.common.str_utils import safe_str, truncate
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults, extract_iocs_from_text_blob
from assemblyline_service_utilities.common.tag_helper import add_tag
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTableSection, ResultTextSection

from tools.ps1_profiler import (
    DEOBFUS_FILE_PREFIX,
    REGEX_INDICATORS,
    STR_INDICATORS,
    SUSPICIOUS_BEHAVIOUR_COMBO,
    profile_ps1,
)

TRANSLATE_SCORE = {
    1.0: 10,  # Low Risk (0-14% hit rate)
    2.0: 100,  # Mild Risk (15-34% hit rate)
    3.0: 500,  # Moderate Risk (35-64% hit rate)
    4.0: 750,  # Moderate Risk (65-84% hit rate)
    5.0: 900,  # Elevated Risk (85-94% hit rate)
    6.0: 1000,  # Malware (95-100% hit rate)
}

DOWNLOAD_FILE_REGEX = re.compile(r"\[.+\] Download From: (.+) --> Save To: (.+)\n", re.IGNORECASE)
INVOKE_EXPRESSION_ACTION = "[Invoke-Expression]"

# The SHA256 representation when PSDecode creates a fake file when pretending to download something
FAKE_FILE_CONTENT = "d219a254440b9cd5094ea46128bd14f0eed3b644d31ea4854806c0cfe8e3b9f8"

# This regular expression is used to find GPG keys statically in the code
GPG_KEY_REGEX = re.compile(r"(?:^|\n).*\becho\b\s*['\"]([a-zA-Z0-9]+)['\"]\s*\|.*\bgpg\b.*")

# Enumerations
PSDECODE = "PSDecode"
# BOX_PS = "Box-PS"
PS1_PROFILER = "PowerShellProfiler"

# Name of clean execution directory to set the cwd of subprocesses to
EXECUTION_DIR = "execution_dir"

class Overpower(ServiceBase):
    def __init__(self, config: dict | None = None) -> None:
        super(Overpower, self).__init__(config)
        self.artifact_hashes: set[str] = set()
        self.artifact_list: dict[dict[str, Any]] = {}
        self.identify = get_identify(use_cache=os.environ.get("PRIVILEGED", "false").lower() == "true")
        self.safelist: dict[str, dict[str, list[str]]] = {}

    def start(self):
        try:
            self.safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")
            self.safelist = {}

    def _run_tool(
        self,
        tool_name: str,
        args: list[str],
        resp: dict[str, Any],
    ) -> None:
        """
        This method runs a tool and appends the stdout from that tool to the dictionary
        :param tool_name: The name of the tool to be run
        :param args: A list of arguments to use to run the tool
        :param resp: A dictionary used to contain the stdout from a tool
        :return: None
        """
        self.log.debug(f"Running {tool_name}...")
        start_time = time()
        resp[tool_name] = []
        try:
            # Stream stdout to resp rather than waiting for process to finish
            with subprocess.Popen(
                args=args,
                stdout=subprocess.PIPE,
                bufsize=1,
                universal_newlines=True,
            ) as p:
                for line in p.stdout:
                    resp[tool_name].append(line)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.log.warning(f"{tool_name} crashed due to {repr(e)}")
        self.log.debug(f"Completed running {tool_name}! Time elapsed: {round(time() - start_time)}s")

    def _remove_fake_files(self) -> None:
        """
        This method removes fake files since we don't want them to exist on subsequent PSDecode runs
        :return: None
        """
        for file in sorted(os.listdir(self.working_directory)):
            file_path = os.path.join(self.working_directory, file)

            if os.path.isdir(file_path):
                continue

            artifact_sha256 = get_sha256_for_file(file_path)

            if artifact_sha256 == FAKE_FILE_CONTENT:
                self.log.debug(f"Removed fake file '{file}' in preparation for subsequent {PSDECODE} run...")
                os.remove(file_path)

    def _setup_psdecode_args(
        self, request: ServiceRequest, tool_timeout: int, fake_web_download: bool = False
    ) -> list[str]:
        psdecode_args = [
            "pwsh",
            "-Command",
            PSDECODE,
            request.file_path,
            "-verbose",
            "-dump",
            self.working_directory,
            "-timeout",
            f"{tool_timeout}",
        ]

        if fake_web_download:
            psdecode_args.append("-fakefile")

        return psdecode_args

    def execute(self, request: ServiceRequest) -> None:
        self.artifact_hashes = set()
        self.artifact_list = {}
        add_supplementary = request.get_param("add_supplementary")
        request.result = Result()
        responses: dict[str, list[str]] = {}

        # Set up clean directory for execution
        execution_dir = os.path.join(self.working_directory, EXECUTION_DIR)
        os.mkdir(execution_dir)

        # PSDecode performs deobfuscating prior to execution with the given timeout. Provide some time to perform
        # the deobfuscation when setting the tool_timeout param...
        fake_web_download = request.get_param("fake_web_download")
        tool_timeout = request.get_param("tool_timeout")

        psdecode_args = self._setup_psdecode_args(request, tool_timeout, fake_web_download)
        # PSDecode may drop things in the shell's current working directory, switching to a clean one
        with chdir(execution_dir):
            psdecode_thr = Thread(target=self._run_tool, args=(PSDECODE, psdecode_args, responses), daemon=True)
            psdecode_thr.start()
            psdecode_thr.join(timeout=tool_timeout)
            if psdecode_thr.is_alive():
                self.log.debug(f"{PSDECODE} did not finish. Look at previous logs...")
                # Give the tool a chance to clean up after to the tool timeout
                sleep(3)

        self._handle_psdecode_output(responses[PSDECODE], request)

        # PowerShellProfiler
        rerun_psdecode = False
        files_to_profile = [(request.file_name, request.file_path)]
        files_to_profile.extend(
            [
                (layer, os.path.join(self.working_directory, layer))
                for layer in sorted(os.listdir(self.working_directory))
                if "layer" in layer
            ]
        )
        total_ps1_profiler_output: dict[str, Any] = {}
        # We do not want a loop of PowerShellProfiler extractions
        if request.temp_submission_data.get("deobfuscated_by_ps1profiler") and request.task.file_name.startswith(
            DEOBFUS_FILE_PREFIX
        ):
            pass
        else:
            start_time = time()
            self.log.debug(f"Starting {PS1_PROFILER}...")
            for file_to_profile, file_path in files_to_profile:
                self.log.debug(f"Profiling {file_to_profile}")
                total_ps1_profiler_output[file_to_profile] = profile_ps1(file_path, self.working_directory)
                do_we_rerun_psdecode = self._handle_ps1_profiler_output(
                    total_ps1_profiler_output[file_to_profile], request.result, file_to_profile
                )

                # If we already ran PSDecode with faking web downloads, and it is determined that
                # we should re-run PSDecode, then do so
                if not rerun_psdecode and do_we_rerun_psdecode and fake_web_download:
                    rerun_psdecode = True

                self.log.debug(f"Completed profiling {file_to_profile}")

            time_elapsed = time() - start_time
            self.log.debug(f"{PS1_PROFILER} took {round(time_elapsed)}s to complete.")

        if rerun_psdecode:
            # First, remove fake files
            self._remove_fake_files()
            # We do not want to fake a successful web download on this second run
            responses[PSDECODE].clear()
            psdecode_args = self._setup_psdecode_args(request, tool_timeout)
            with chdir(execution_dir):
                psdecode_thr = Thread(target=self._run_tool, args=(PSDECODE, psdecode_args, responses), daemon=True)
                psdecode_thr.start()
                psdecode_thr.join(timeout=tool_timeout)
                if psdecode_thr.is_alive():
                    self.log.debug(f"{PSDECODE} did not finish. Look at previous logs...")
                    # Give the tool a chance to clean up after to the tool timeout
                    sleep(3)
            self._handle_psdecode_output(responses[PSDECODE], request, subsequent_run=True)

        self.gpg_key_hunter(request)

        if add_supplementary:
            self._extract_supplementary(total_ps1_profiler_output, responses[PSDECODE])

        worth_extracting = len(request.result.sections) > 0
        self.artifact_hashes.add(request.sha256)
        self._prepare_artifacts(request, worth_extracting)

        # Adding sandbox artifacts using the OntologyResults helper class
        _ = OntologyResults.handle_artifacts(list(self.artifact_list.values()), request)

    def _handle_ps1_profiler_output(self, output: dict[str, Any], result: Result, file_name: str) -> bool:
        """
        This method converts the output from the PowerShellProfiler tool into ResultSections
        :param output: The output from the PowerShellProfiler tool
        :param result: A Result object containing the service results
        :param file_name: The name of the file which was profiled
        :return: A flag indicating that we need to re-run PSDecode
        """
        # Get previous result sections for handling PowerShellProfiler profiles
        previous_signatures: list[str] = []
        previous_families: list[str] = []
        previous_iocs: list[tuple[str, str]] = []
        static_uri_counter = 0
        for section in result.sections:
            for subsection in section.subsections:
                if subsection.heuristic:
                    previous_signatures.extend(list(subsection.heuristic.signatures.keys()))
            if section.tags:
                for tag, values in section.tags.items():
                    if tag == "attribution.family":
                        previous_families.extend(values)
            if "IOC(s) extracted" in section.title_text:
                for tag, values in section.tags.items():
                    for value in values:
                        if (tag, value) not in previous_iocs:
                            previous_iocs.append((tag, value))
                            if tag == "network.static.uri":
                                static_uri_counter += 1

        suspicious_res_sec = ResultTextSection("Placeholder")
        # Check if there is a malware family detected
        if len(output["families"]) > 0 and not all(family in previous_families for family in output["families"]):
            suspicious_res_sec.title_text = f"Malicious Content Detected in {file_name}"
            suspicious_res_sec.set_heuristic(2)
            for family, values in output["families"].items():
                suspicious_res_sec.add_tag("attribution.family", family)
                suspicious_res_sec.add_line(f"Attribution family: {family}")
                if len(values[REGEX_INDICATORS]) > 0:
                    suspicious_res_sec.add_line("\tMatched regular expressions:")
                    for regex_indicator in values[REGEX_INDICATORS]:
                        suspicious_res_sec.add_line(f"\t\t{regex_indicator}")
                if len(values[STR_INDICATORS]) > 0:
                    suspicious_res_sec.add_line("\tMatched any or all strings:")
                    for str_indicator in values[STR_INDICATORS]:
                        suspicious_res_sec.add_line(f"\t\t{str_indicator}")
        # Otherwise, the behaviour is just suspicious
        else:
            suspicious_res_sec.title_text = f"Suspicious Content Detected in {file_name}"

        suspicious_behaviour_combo_url_sig = False
        for tag, details in output["behaviour"].items():
            if details["score"] < 0:
                # According to the PowerShell Profiler, if a score is < 0, then the script can be generally assumed
                # to be benign. But we don't assume anything!
                continue
            # If a signature was raised in a previous layer profile, then don't report it
            if tag in previous_signatures:
                continue
            profiler_sig_section = ResultTextSection(
                title_text=f"Signature: {tag}",
                parent=suspicious_res_sec,
            )
            if details.get("marks"):
                profiler_sig_section.add_line(f"Marks: {', '.join(details['marks'])}")

                # Special Mshta Downloader case
                if tag == "Mshta" and len(details["marks"]) == 2:
                    profiler_sig_section.set_heuristic(6)
                    _ = add_tag(profiler_sig_section, "network.static.uri", details["marks"][1])
                    profiler_sig_section.heuristic.add_signature_id(tag)

            if profiler_sig_section.heuristic is None:
                profiler_sig_section.set_heuristic(3)
                translated_score = TRANSLATE_SCORE[details["score"]]
                profiler_sig_section.heuristic.add_signature_id(tag, score=translated_score)

            if tag == SUSPICIOUS_BEHAVIOUR_COMBO:
                # If there is a suspicious behaviour combo seen, we should flag the IOCs seen in actions with a signature that scores 500
                for result_section in result.sections:
                    if (
                        result_section.heuristic
                        and result_section.heuristic.heur_id in [5, 7]
                        and any("network" in key for key in result_section.tags.keys())
                    ):
                        self.log.debug(
                            "Added the suspicious_behaviour_combo_url signature to the result section to score the tagged URLs"
                        )
                        result_section.heuristic.add_signature_id("suspicious_behaviour_combo_url")
                        suspicious_behaviour_combo_url_sig = True

        if len(suspicious_res_sec.subsections) > 0 or suspicious_res_sec.heuristic is not None:
            result.add_section(suspicious_res_sec)

        extracted_cap = 10
        number_of_extracted = 0
        for index, extracted in enumerate(output["extracted"]):
            if number_of_extracted >= extracted_cap:
                break

            path_to_write = os.path.join(self.working_directory, f"ps1profiler_{extracted['type']}_{index}")
            with open(path_to_write, "wb") as f:
                f.write(extracted["data"])

            file_type_details = self.identify.fileinfo(path_to_write, generate_hashes=False)
            if file_type_details["type"] in ["unknown", "text/plain"]:
                self.log.debug(f"{path_to_write} was identified as {file_type_details['type']}. Ignoring...")
                os.remove(path_to_write)
                continue

            self.log.debug(f"Wrote {path_to_write} to disk for extraction...")
            number_of_extracted += 1

        if output["deobfuscated"]:
            static_file_lines = []
            for line in safe_str(output["deobfuscated"]).split("\n"):
                if ";" in line:
                    static_file_lines.extend(line.split(";"))
                else:
                    static_file_lines.append(line)
            ioc_res_sec = ResultTableSection(f"IOC(s) extracted from {file_name}")
            for static_file_line in static_file_lines:
                extract_iocs_from_text_blob(
                    truncate(static_file_line, 1000), ioc_res_sec, is_network_static=True, safelist=self.safelist
                )
            if ioc_res_sec.body:
                # Removing duplicate IOCs
                for tag, values in ioc_res_sec.tags.items():
                    for value in values[:]:
                        if (tag, value) in previous_iocs:
                            values.remove(value)

                tags_to_remove: set[str] = set()
                for tag in ioc_res_sec.tags:
                    if not ioc_res_sec.tags[tag]:
                        tags_to_remove.add(tag)
                for tag in tags_to_remove:
                    ioc_res_sec.tags.pop(tag)
                if ioc_res_sec.tags:
                    ioc_res_sec.set_heuristic(1)
                    result.add_section(ioc_res_sec)

                # If we see a suspicious behaviour combination being used, were able to
                # attribute it to a URL, and there are multiple URLs extracted statically, it's
                # worth running PSDecode again
                if suspicious_behaviour_combo_url_sig and (
                    len(ioc_res_sec.tags.get("network.static.uri", [])) > 2 or static_uri_counter > 3
                ):
                    return True

        return False

    def _handle_psdecode_output(self, output: list[str], request: ServiceRequest, subsequent_run: bool = False) -> None:
        """
        This method converts the output from the PSDecode tool into ResultSections
        :param output: The output from the PSDecode tool
        :param request: The ServiceRequest object
        :param subsequent_run: A boolean indicating if this output is from a subsquent run of PSDecode
        :return: None
        """
        actions: list[str] = []
        for index, line in enumerate(output):
            if "############################## Actions ##############################" in line:
                actions = output[index + 1 :]
                break
        if not subsequent_run:
            psdecode_actions_res_sec = ResultTextSection(f"Interesting actions captured by {PSDECODE}")
        else:
            psdecode_actions_res_sec = ResultTextSection(
                f"Interesting actions captured with subsequent run of {PSDECODE}"
            )

        psdecode_actions_res_sec.set_heuristic(5)

        # If this is the second run of PSDecode, we are confident that the IOCs we are going to see are worth scoring.
        if subsequent_run:
            psdecode_actions_res_sec.heuristic.add_signature_id("suspicious_behaviour_combo_url")

        psdecode_actions_res_sec.add_lines(
            [action[:500] + "..." if len(action) > 500 else action for action in actions]
        )
        actions_ioc_table = ResultTableSection("IOCs found in actions")
        iex_count = 0
        urls_seen_in_actions: set[str] = set()
        paths_seen_in_actions: set[str] = set()
        for action in actions:
            static_iocs = False
            if action.startswith(INVOKE_EXPRESSION_ACTION):
                static_iocs = True  # iEX calls have the same false positives as static powershell scripts
                iex_count += 1
            extract_iocs_from_text_blob(action, actions_ioc_table, is_network_static=static_iocs)
            match = DOWNLOAD_FILE_REGEX.search(action)
            if match and len(match.regs) == 3:
                url = match.group(1)
                urls_seen_in_actions.add(url)
                path = match.group(2)
                paths_seen_in_actions.add(path)
                was_tag_added = add_tag(psdecode_actions_res_sec, "network.dynamic.uri", url)
                if not was_tag_added:
                    psdecode_actions_res_sec.add_tag("file.string.extracted", url)
                psdecode_actions_res_sec.add_tag("file.path", path)

            if action.startswith("[Start-Process]") and paths_seen_in_actions:
                # The only way we get here is if a DOWNLOAD_FILE_REGEX hit exists, which means a file was downloaded
                # from a URL to disk
                for path_seen in paths_seen_in_actions:
                    if path_seen in action or path_seen.startswith("./") and path_seen[2:] in action:
                        for url_seen in urls_seen_in_actions:
                            request.add_extracted_uri("File downloaded and executed", uri=url_seen)
            elif action.startswith("[Invoke-RestMethod] POST") and "api.telegram.org" in action:
                psdecode_actions_res_sec.heuristic.add_signature_id("telegram_post")

        if iex_count >= 3:
            psdecode_actions_res_sec.heuristic.add_signature_id("multiple_iex_calls", 250)

        if actions_ioc_table.body:
            actions_ioc_table.set_heuristic(1)
            psdecode_actions_res_sec.add_subsection(actions_ioc_table)
        if psdecode_actions_res_sec.body:
            request.result.add_section(psdecode_actions_res_sec)

    def _extract_supplementary(self, ps1_profiler_output: dict[str, Any], psdecode_output: list[str]) -> None:
        """
        This method adds the stdout/output from tools as supplementary files
        :param ps1_profiler_output: A dictionary containing details from the PowerShellProfiler tool
        :param psdecode_output: A list of strings where each string is a line of stdout from the PSDecode tool
        :return: None
        """
        if ps1_profiler_output:
            ps1_profiler_suppl_path = os.path.join(self.working_directory, "suppl_ps1_profiler_output.json")
            ps1_profiler_output_copy = deepcopy(ps1_profiler_output)
            if any(values.get("extracted") for values in ps1_profiler_output_copy.values()):
                for values in ps1_profiler_output_copy.values():
                    for item in values["extracted"]:
                        if isinstance(item["data"], bytes):
                            item["data"] = safe_str(item["data"])
            with open(ps1_profiler_suppl_path, "w") as f:
                f.write(json.dumps(ps1_profiler_output_copy))
        if psdecode_output:
            psdecode_suppl_path = os.path.join(self.working_directory, "suppl_psdecode_output.txt")
            with open(psdecode_suppl_path, "w") as f:
                f.writelines(psdecode_output)

    def _prepare_artifacts(self, request: ServiceRequest, worth_extracting: bool = True) -> None:
        """
        This method prepares artifacts that have been dumped by PowerShell de-obfuscation tools
        :param request: The ServiceRequest object
        :param worth_extracting: A flag indicating if we should extract files or not.
        :return: None
        """
        execution_dir = os.path.join(self.working_directory, EXECUTION_DIR)
        execution_files = {file for _, _, files in os.walk(execution_dir) for file in files}

        # Retrieve artifacts
        for root, _, files in os.walk(self.working_directory):
            for file in sorted(files):
                file_path = os.path.join(root, file)

                artifact_sha256 = get_sha256_for_file(file_path)

                if artifact_sha256 == FAKE_FILE_CONTENT:
                    continue

                if artifact_sha256 in self.artifact_hashes:
                    self.log.debug(f"Ignoring {file_path} since it is a duplicate extracted file...")
                    # We also want to rename the artifact that this file is a duplicate of
                    # to avoid naming conflicts
                    artifact = self.artifact_list.get(artifact_sha256, None)
                    if artifact:
                        artifact["name"] = artifact_sha256
                        # If there is an extracted file with the same hash as a layer file from PSDecode, then set
                        # that file to supplementary
                        if "layer" in file and artifact["to_be_extracted"]:
                            self.log.debug(f"Setting artifact {artifact_sha256} to supplmentary")
                            artifact["to_be_extracted"] = False
                    continue
                self.artifact_hashes.add(artifact_sha256)
                to_be_extracted = True
                if file.startswith(DEOBFUS_FILE_PREFIX):
                    description = f"De-obfuscated layer from {PS1_PROFILER}"
                    request.temp_submission_data["deobfuscated_by_ps1profiler"] = True
                elif file.startswith("layer"):
                    description = f"Layer of de-obfuscated PowerShell from {PSDECODE}"
                    # We don't want to extract these since it is redundant. PSDecode already ran on them.
                    to_be_extracted = False
                elif file.startswith("suppl_"):
                    description = "Output from PowerShell tool"
                    to_be_extracted = False
                else:
                    description = "Overpower Dump"
                    to_be_extracted = True

                if not worth_extracting and to_be_extracted:
                    self.log.debug(f"Ignoring {file_path} since the parent file is not interesting.")
                    continue

                self.artifact_list[artifact_sha256] = {
                    "name": file,
                    "path": file_path,
                    "description": description,
                    "to_be_extracted": to_be_extracted,
                    "sha256": artifact_sha256,
                }

                if file in execution_files:
                    file_type_details = self.identify.fileinfo(file_path, generate_hashes=False)
                    self._handle_specific_written_files(file_type_details["type"], file_path, request.result)

        for artifact in self.artifact_list.values():
            self.log.debug(
                f"Adding extracted file: {artifact['path']}"
                if artifact["to_be_extracted"]
                else f"Adding supplementary file: {artifact['path']}"
            )

    @staticmethod
    def _handle_specific_written_files(file_type: str, file_path: str, result: Result) -> None:
        """
        This method looks for iocs in batch files and assigns signatures if applicable
        :param file_type: The type of the written file to be handled
        :param file_path: The path of the written file to be handled
        :param result: A Result object containing the service results
        :return: None
        """
        if file_type == "code/batch":
            with open(file_path, "r", encoding="CP850") as f:
                body = f.read()
            url_sec = ResultTableSection("IOCs found in extracted batch file")
            extract_iocs_from_text_blob(body, url_sec, is_network_static=True)
            if url_sec.body and url_sec.tags.get("network.static.uri"):
                url_sec.set_heuristic(4)
                url_sec.heuristic.add_signature_id("suspicious_url_found")
                result.add_section(url_sec)

    @staticmethod
    def gpg_key_hunter(request: ServiceRequest) -> None:
        """
        This method looks for GPG keys statically used in the code
        :param request: The ServiceRequest object
        :return: None
        """
        file_contents = request.file_contents
        try:
            encoding = "utf-16" if file_contents.startswith(b"\xff\xfe") else "utf-8"
            matches = GPG_KEY_REGEX.findall(file_contents.decode(encoding))
        except Exception:
            return

        if not matches:
            return

        if "passwords" in request.temp_submission_data and isinstance(request.temp_submission_data["passwords"], list):
            request.temp_submission_data["passwords"].extend(set(matches))
            request.temp_submission_data["passwords"].sort()
        else:
            request.temp_submission_data["passwords"] = sorted(set(matches))
