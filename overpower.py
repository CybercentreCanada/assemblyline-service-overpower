import re
from json import dumps
from os import environ, getcwd, listdir, path, remove, rmdir, walk
from shutil import copy
from subprocess import PIPE, Popen, TimeoutExpired
from time import time
from typing import Any, Dict, List, Optional, Set, Tuple

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.forge import get_identify
from assemblyline.common.str_utils import safe_str, truncate
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import OntologyResults, extract_iocs_from_text_blob
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTableSection, ResultTextSection
from assemblyline_v4_service.common.tag_helper import add_tag
from tools.ps1_profiler import DEOBFUS_FILE, REGEX_INDICATORS, STR_INDICATORS, SUSPICIOUS_BEHAVIOUR_COMBO, profile_ps1

TRANSLATE_SCORE = {
    1.0: 10,  # Low Risk (0-14% hit rate)
    2.0: 100,  # Mild Risk (15-34% hit rate)
    3.0: 500,  # Moderate Risk (35-64% hit rate)
    4.0: 750,  # Moderate Risk (65-84% hit rate)
    5.0: 900,  # Elevated Risk (85-94% hit rate)
    6.0: 1000,  # Malware (95-100% hit rate)
}

DOWNLOAD_FILE_REGEX = "\[.+\] Download From: (.+) --> Save To: (.+)\n"

# The SHA256 representation when PSDecode creates a fake file when pretending to download something
FAKE_FILE_CONTENT = "d219a254440b9cd5094ea46128bd14f0eed3b644d31ea4854806c0cfe8e3b9f8"


class Overpower(ServiceBase):

    def __init__(self, config: Optional[Dict] = None) -> None:
        super(Overpower, self).__init__(config)
        self.artifact_hashes = None
        self.artifact_list = None
        self.safe_file_list = [path.join(root, file) for root, _, files in walk(getcwd()) for file in files]
        self.identify = get_identify(use_cache=environ.get('PRIVILEGED', 'false').lower() == 'true')

    def _run_psdecode(self, request: ServiceRequest, fake_web_download: bool = True) -> List[str]:
        """
        This method runs the PSDecode tool and returns what was written to STDOUT
        :param request: The ServiceRequest object
        :param fake_web_download: A flag that is used for indicating if a web request to download a file to disk should be faked.
        :return: A list of strings representing each line that PSDecode wrote to STDOUT
        """
        tool_timeout = request.get_param("tool_timeout")

        args = [
            "pwsh", "-Command", "PSDecode", request.file_path,
            "-verbose",
            "-dump", self.working_directory,
            "-timeout", f"{tool_timeout}",
        ]

        if fake_web_download:
            args.append("-fakefile")

        start_time = time()
        psdecode_output: List[str] = []
        self.log.debug("Starting PSDecode...")
        try:
            # PSDecode performs deobfuscating prior to execution with the given timeout. Provide some time to perform
            # the deobfuscation when setting the tool_timeout param...
            # Stream stdout to resp rather than waiting for process to finish
            with Popen(args=args, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
                for line in p.stdout:
                    psdecode_output.append(line)
        except TimeoutExpired:
            self.log.debug(f"PSDecode took longer than {tool_timeout}s to complete.")

        time_elapsed = time() - start_time
        self.log.debug(f"PSDecode took {round(time_elapsed)}s to complete.")

        return psdecode_output

    def _move_unsafe_new_files_to_working_dir(self) -> Set[str]:
        """
        Since we are running samples right on the Docker container, there is a chance that samples could drop
        files to the root directory of execution
        :return: A set containing the file paths of the files that were moved
        """

        unsafe_file_list = [path.join(root, file) for root, _, files in walk(getcwd()) for file in files]
        files_to_move = set(unsafe_file_list).difference(set(self.safe_file_list))
        for file_to_move in files_to_move:
            copy(file_to_move, self.working_directory)
            remove(file_to_move)
        return files_to_move

    def _remove_fake_files(self) -> None:
        """
        This method removes fake files since we don't want them to exist on subsequent PSDecode runs
        :return: None
        """
        _ = self._move_unsafe_new_files_to_working_dir()

        for file in sorted(listdir(self.working_directory)):
            file_path = path.join(self.working_directory, file)

            artifact_sha256 = get_sha256_for_file(file_path)

            if artifact_sha256 in [FAKE_FILE_CONTENT]:
                self.log.debug(f"Removed fake file '{file}' in preparation for subsequent PSDecode run...")
                remove(file_path)

    def execute(self, request: ServiceRequest) -> None:
        self.artifact_hashes = set()
        self.artifact_list: List[Dict[str, Any]] = []
        add_supplementary = request.get_param("add_supplementary")
        request.result = Result()

        # PSDecode
        fake_web_download = request.get_param("fake_web_download")
        psdecode_output = self._run_psdecode(request, fake_web_download=fake_web_download)
        self._handle_psdecode_output(psdecode_output, request.result)

        # PowerShellProfiler
        rerun_psdecode = False
        files_to_profile = [(request.file_name, request.file_path)]
        files_to_profile.extend([(layer, path.join(self.working_directory, layer))
                                for layer in sorted(listdir(self.working_directory)) if "layer" in layer])
        total_ps1_profiler_output: Dict[str, Any] = {}
        start_time = time()
        self.log.debug("Starting PowerShellProfiler...")
        for file_to_profile, file_path in files_to_profile:
            self.log.debug(f"Profiling {file_to_profile}")
            total_ps1_profiler_output[file_to_profile] = profile_ps1(file_path, self.working_directory)
            do_we_rerun_psdecode = self._handle_ps1_profiler_output(
                total_ps1_profiler_output[file_to_profile],
                request.result, file_to_profile)

            # If we already ran PSDecode with faking web downloads, and it is determined that
            # we should re-run PSDecode, then do so
            if not rerun_psdecode and do_we_rerun_psdecode and fake_web_download:
                rerun_psdecode = True

            self.log.debug(f"Completed profiling {file_to_profile}")

        time_elapsed = time() - start_time
        self.log.debug(f"PS1Profiler took {round(time_elapsed)}s to complete.")

        if rerun_psdecode:
            # First, remove fake files
            self._remove_fake_files()
            # We do not want to fake a successful web download on this second run
            psdecode_output = self._run_psdecode(request, fake_web_download=False)
            self._handle_psdecode_output(psdecode_output, request.result, subsequent_run=True)

        if add_supplementary:
            self._extract_supplementary(total_ps1_profiler_output, psdecode_output)

        worth_extracting = len(request.result.sections) > 0
        self.artifact_hashes.add(request.sha256)
        self._prepare_artifacts(request.result, worth_extracting)

        # Adding sandbox artifacts using the OntologyResults helper class
        _ = OntologyResults.handle_artifacts(self.artifact_list, request)

    def _handle_ps1_profiler_output(self, output: Dict[str, Any], result: Result, file_name: str) -> bool:
        """
        This method converts the output from the PowerShellProfiler tool into ResultSections
        :param output: The output from the PowerShellProfiler tool
        :param result: A Result object containing the service results
        :param file_name: The name of the file which was profiled
        :return: A flag indicating that we need to re-run PSDecode
        """
        # Get previous result sections for handling PowerShellProfiler profiles
        previous_signatures: List[str] = []
        previous_families: List[str] = []
        previous_iocs: List[Tuple[str, str]] = []
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
            if details.get('marks'):
                profiler_sig_section.add_line(f"Marks: {', '.join(details['marks'])}")
            profiler_sig_section.set_heuristic(3)
            translated_score = TRANSLATE_SCORE[details["score"]]
            profiler_sig_section.heuristic.add_signature_id(tag, score=translated_score)

            if tag == SUSPICIOUS_BEHAVIOUR_COMBO:
                # If there is a suspicious behaviour combo seen, we should flag the IOCs seen in actions with a signature that scores 500
                for result_section in result.sections:
                    if result_section.heuristic and result_section.heuristic.heur_id == 5 and any("network" in key for key in result_section.tags.keys()):
                        self.log.debug("Added the suspicious_behaviour_combo_url signature to the result section to score the tagged URLs")
                        result_section.heuristic.add_signature_id("suspicious_behaviour_combo_url")
                        suspicious_behaviour_combo_url_sig = True
                        break

        if len(suspicious_res_sec.subsections) > 0 or suspicious_res_sec.heuristic is not None:
            result.add_section(suspicious_res_sec)

        extracted_cap = 10
        number_of_extracted = 0
        for index, extracted in enumerate(output["extracted"]):
            if number_of_extracted >= extracted_cap:
                break

            path_to_write = path.join(self.working_directory, f"ps1profiler_{extracted['type']}_{index}")
            with open(path_to_write, "wb") as f:
                f.write(extracted["data"])

            file_type_details = self.identify.fileinfo(path_to_write)
            if file_type_details["type"] in ["unknown", "text/plain"]:
                self.log.debug(f"{path_to_write} was identified as {file_type_details['type']}. Ignoring...")
                remove(path_to_write)
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
                extract_iocs_from_text_blob(truncate(static_file_line, 1000), ioc_res_sec, is_network_static=True)
            if ioc_res_sec.body:
                # Removing duplicate IOCs
                for tag, values in ioc_res_sec.tags.items():
                    for value in values[:]:
                        if (tag, value) in previous_iocs:
                            values.remove(value)

                tags_to_remove: Set[str] = set()
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
                if suspicious_behaviour_combo_url_sig and (len(ioc_res_sec.tags.get("network.static.uri", [])) > 2 or static_uri_counter > 3):
                    return True

        return False

    def _handle_psdecode_output(self, output: List[str], result: Result, subsequent_run: bool = False) -> None:
        """
        This method converts the output from the PSDecode tool into ResultSections
        :param output: The output from the PSDecode tool
        :param result: A Result object containing the service results
        :param subsequent_run: A boolean indicating if this output is from a subsquent run of PSDecode
        :return: None
        """
        actions: List[str] = []
        for index, line in enumerate(output):
            if "############################## Actions ##############################" in line:
                actions = output[index + 1:]
                break
        if not subsequent_run:
            psdecode_actions_res_sec = ResultTextSection("Actions detected with PSDecode")
        else:
            psdecode_actions_res_sec = ResultTextSection("Actions detected with subsequent run of PSDecode")

        psdecode_actions_res_sec.set_heuristic(5)

        # If this is the second run of PSDecode, we are confident that the IOCs we are going to see are worth scoring.
        if subsequent_run:
            psdecode_actions_res_sec.heuristic.add_signature_id("suspicious_behaviour_combo_url")

        psdecode_actions_res_sec.add_lines(actions)
        actions_ioc_table = ResultTableSection("IOCs found in actions")
        for action in actions:
            extract_iocs_from_text_blob(action, actions_ioc_table)

            match = re.search(DOWNLOAD_FILE_REGEX, action, re.IGNORECASE)
            if match and len(match.regs) == 3:
                url = match.group(1)
                path = match.group(2)
                was_tag_added = add_tag(psdecode_actions_res_sec, "network.dynamic.uri", url)
                if not was_tag_added:
                    psdecode_actions_res_sec.add_tag("file.string.extracted", url)
                psdecode_actions_res_sec.add_tag("file.path", path)

        if actions_ioc_table.body:
            actions_ioc_table.set_heuristic(1)
            psdecode_actions_res_sec.add_subsection(actions_ioc_table)
        if psdecode_actions_res_sec.body:
            result.add_section(psdecode_actions_res_sec)

    def _extract_supplementary(self, ps1_profiler_output: Dict[str, Any], psdecode_output: List[str]) -> None:
        """
        This method adds the stdout/output from tools as supplementary files
        :param ps1_profiler_output: A dictionary containing details from the PowerShellProfiler tool
        :param psdecode_output: A list of strings where each string is a line of stdout from the PSDecode tool
        :return: None
        """
        if ps1_profiler_output:
            ps1_profiler_suppl_path = path.join(self.working_directory, "suppl_ps1_profiler_output.json")
            with open(ps1_profiler_suppl_path, "w") as f:
                f.write(dumps(ps1_profiler_output))
        if psdecode_output:
            psdecode_suppl_path = path.join(self.working_directory, "suppl_psdecode_output.txt")
            with open(psdecode_suppl_path, "w") as f:
                f.writelines(psdecode_output)

    def _prepare_artifacts(self, result: Result, worth_extracting: bool = True) -> None:
        """
        This method prepares artifacts that have been dumped by PowerShell de-obfuscation tools
        :param worth_extracting: A flag indicating if we should extract files or not.
        :return: None
        """
        files_to_move = self._move_unsafe_new_files_to_working_dir()

        # Remove empty dirs
        for root, dirs, _ in walk(getcwd()):
            for d in dirs:
                dir_path = path.join(root, d)
                if len(listdir(dir_path)) == 0:
                    rmdir(dir_path)

        # Retrieve artifacts
        for file in sorted(listdir(self.working_directory)):
            file_path = path.join(self.working_directory, file)

            artifact_sha256 = get_sha256_for_file(file_path)

            if artifact_sha256 in [FAKE_FILE_CONTENT]:
                continue

            if artifact_sha256 in self.artifact_hashes:
                self.log.debug(f"Ignoring {file_path} since it is a duplicate extracted file...")
                # We also want to rename the artifact that this file is a duplicate of
                # to avoid naming conflicts
                artifact = next(
                    (artifact for artifact in self.artifact_list if artifact["sha256"] == artifact_sha256),
                    None
                )
                if artifact:
                    artifact["name"] = artifact_sha256
                continue
            else:
                self.artifact_hashes.add(artifact_sha256)
            to_be_extracted = True
            if DEOBFUS_FILE in file:
                description = "De-obfuscated file from PowerShellProfiler"
            elif "layer" in file:
                description = "Layer of de-obfuscated PowerShell from PSDecode"
            elif "suppl" in file:
                description = "Output from PowerShell tool"
                to_be_extracted = False
            else:
                description = "Overpower Dump"
                to_be_extracted = True

            if not worth_extracting and to_be_extracted:
                self.log.debug(f"Ignoring {file_path} since the parent file is not interesting.")
                continue

            self.artifact_list.append({
                "name": file,
                "path": file_path,
                "description": description,
                "to_be_extracted": to_be_extracted,
                "sha256": artifact_sha256,
            })
            self.log.debug(
                f"Adding extracted file: {file_path}"
                if to_be_extracted else f"Adding supplementary file: {file_path}")

            for f in files_to_move:
                if "/" in f:
                    file_name = f.split("/")[-1]
                    if file == file_name:
                        file_type_details = self.identify.fileinfo(file_path)
                        self._handle_specific_written_files(file_type_details["type"], file_path, result)
                        break

    @staticmethod
    def _handle_specific_written_files(file_type: str, file_path: str, result: Result) -> None:
        if file_type == "code/batch":
            with open(file_path, "r") as f:
                body = f.read()
            url_sec = ResultTableSection("IOCs found in extracted batch file")
            extract_iocs_from_text_blob(body, url_sec, is_network_static=True)
            if url_sec.body and url_sec.tags.get("network.static.uri"):
                url_sec.set_heuristic(4)
                url_sec.heuristic.add_signature_id("suspicious_url_found")
                result.add_section(url_sec)
