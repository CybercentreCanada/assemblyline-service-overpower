from json import dumps
from os import path, listdir
from subprocess import run, TimeoutExpired
from typing import Optional, Dict, Any, List, Set, Tuple

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.str_utils import safe_str, truncate
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import extract_iocs_from_text_blob, SandboxOntology
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultTextSection, ResultTableSection

from tools.ps1_profiler import profile_ps1, DEOBFUS_FILE, REGEX_INDICATORS, STR_INDICATORS

TRANSLATE_SCORE = {
    1.0: 10,  # Low Risk
    2.0: 100,  # Mild Risk
    3.0: 500,  # Moderate Risk
    4.0: 750,  # Moderate Risk
    5.0: 900,  # Elevated Risk
    6.0: 1000,  # Malware
}


class Overpower(ServiceBase):

    def __init__(self, config: Optional[Dict] = None) -> None:
        super(Overpower, self).__init__(config)
        self.artifact_hashes = None
        self.artifact_list = None

    def execute(self, request: ServiceRequest) -> None:
        self.artifact_hashes = set()
        self.artifact_list: List[Dict[str, Any]] = []
        tool_timeout = request.get_param("tool_timeout")
        add_supplementary = request.get_param("add_supplementary")
        request.result = Result()

        # PSDecode
        args = [
            "pwsh", "-Command", "PSDecode", request.file_path,
            "-verbose",
            "-dump", self.working_directory,
            "-timeout", f"{tool_timeout}"
        ]
        try:
            completed_process = run(args=args, capture_output=True, timeout=tool_timeout)
        except TimeoutExpired:
            self.log.debug(f"PSDecode took longer than {tool_timeout}s to complete.")
            completed_process = None

        psdecode_output = []
        if completed_process:
            psdecode_output = completed_process.stdout.decode().split("\n")
            psdecode_error = completed_process.stderr.decode()
            if psdecode_error:
                self.log.warning(f"When running PSDecode, the following error was raised: {psdecode_error}")
        self._handle_psdecode_output(psdecode_output, request.result)

        # PowerShellProfiler
        files_to_profile = [(request.file_name, request.file_path)]
        files_to_profile.extend([(layer, path.join(self.working_directory, layer))
                                for layer in sorted(listdir(self.working_directory)) if "layer" in layer])
        total_ps1_profiler_output: Dict[str, Any] = {}
        for file_to_profile, file_path in files_to_profile:
            total_ps1_profiler_output[file_to_profile] = profile_ps1(file_path, self.working_directory)
            self._handle_ps1_profiler_output(
                total_ps1_profiler_output[file_to_profile],
                request.result, file_to_profile)

        if add_supplementary:
            self._extract_supplementary(total_ps1_profiler_output, psdecode_output)

        worth_extracting = len(request.result.sections) > 0
        self._prepare_artifacts(worth_extracting)

        # Adding sandbox artifacts using the SandboxOntology helper class
        _ = SandboxOntology.handle_artifacts(self.artifact_list, request)

    def _handle_ps1_profiler_output(self, output: Dict[str, Any], result: Result, file_name: str) -> None:
        """
        This method converts the output from the PowerShellProfiler tool into ResultSections
        :param output: The output from the PowerShellProfiler tool
        :param result: A Result object containing the service results
        :param file_name: The name of the file which was profiled
        :return: None
        """
        # Get previous result sections for handling PowerShellProfiler profiles
        previous_signatures: List[str] = []
        previous_families: List[str] = []
        previous_iocs: List[Tuple[str, str]] = []
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

        if len(suspicious_res_sec.subsections) > 0 or suspicious_res_sec.heuristic is not None:
            result.add_section(suspicious_res_sec)

        extracted_cap = 10
        number_of_extracted = 0
        for index, extracted in enumerate(output["extracted"]):
            if number_of_extracted >= extracted_cap:
                break
            with open(path.join(self.working_directory, f"ps1profiler_{extracted['type']}_{index}"), "wb") as f:
                f.write(extracted["data"])
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
                extract_iocs_from_text_blob(truncate(static_file_line, 1000), ioc_res_sec)
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

    def _handle_psdecode_output(self, output: List[str], result: Result) -> None:
        """
        This method converts the output from the PSDecode tool into ResultSections
        :param output: The output from the PSDecode tool
        :param result: A Result object containing the service results
        :return: None
        """
        actions: List[str] = []
        for index, line in enumerate(output):
            if "############################## Actions ##############################" in line:
                actions = output[index + 1:]
        psdecode_actions_res_sec = ResultTextSection("Actions detected with PSDecode")
        psdecode_actions_res_sec.add_lines(actions)
        actions_ioc_table = ResultTableSection("IOCs found in actions")
        for action in actions:
            extract_iocs_from_text_blob(action, actions_ioc_table)
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

    def _prepare_artifacts(self, worth_extracting: bool = True) -> None:
        """
        This method prepares artifacts that have been dumped by PowerShell de-obfuscation tools
        :param worth_extracting: A flag indicating if we should extract files or not.
        :return: None
        """
        # Retrieve artifacts
        for file in sorted(listdir(self.working_directory)):
            file_path = path.join(self.working_directory, file)

            artifact_sha256 = get_sha256_for_file(file_path)
            if artifact_sha256 in self.artifact_hashes:
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
                "to_be_extracted": to_be_extracted
            })
            self.log.debug(
                f"Adding extracted file: {file_path}"
                if to_be_extracted else f"Adding supplementary file: {file_path}")
