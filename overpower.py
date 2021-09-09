from hashlib import sha256
from json import dumps
from os import path, listdir
from subprocess import run, TimeoutExpired
from typing import Optional, Dict, Any, List

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection

from tools.ps1_profiler import main as ps1_profiler, DEOBFUS_FILE


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

        # PowerShellProfiler
        ps1_profiler_output = ps1_profiler(request.file_path, self.working_directory)
        self._handle_ps1_profiler_output(ps1_profiler_output, request.result)

        # PSDecode
        args = ["pwsh", "-Command", "PSDecode", request.file_path, "-verbose", "-dump", self.working_directory]
        try:
            completed_process = run(args=args, capture_output=True, timeout=tool_timeout)
        except TimeoutExpired:
            completed_process = None

        psdecode_output = []
        if completed_process:
            psdecode_output = completed_process.stdout.decode().split("\n")
        self._handle_psdecode_output(psdecode_output, request.result)

        if add_supplementary:
            self._extract_supplementary(ps1_profiler_output, psdecode_output)

        # Retrieve artifacts
        for file in listdir(self.working_directory):
            file_path = path.join(self.working_directory, file)
            artifact_sha256 = self.get_id_from_data(file_path)
            if artifact_sha256 in self.artifact_hashes:
                continue
            else:
                self.artifact_hashes.add(artifact_sha256)
            description = "Overpower artifact"
            to_be_extracted = True
            if DEOBFUS_FILE in file:
                description = "De-obfuscated file from PowerShellProfiler"
            elif "layer" in file:
                description = "Layer of de-obfuscated PowerShell from PSDecode"
            elif "suppl" in file:
                description = "Output from PowerShell tool"
                to_be_extracted = False
            self.artifact_list.append({
                "name": file,
                "path": file_path,
                "description": description,
                "to_be_extracted": to_be_extracted
            })
            self.log.debug(f"Adding extracted file: {file_path}" if to_be_extracted else f"Adding supplementary file: {file_path}")

        # Adding sandbox artifacts using the SandboxOntology helper class
        _ = SandboxOntology.handle_artifacts(self.artifact_list, request)

    @staticmethod
    def _handle_ps1_profiler_output(output: Dict[str, Any], result: Result) -> None:
        """
        This method converts the output from the PowerShellProfiler tool into ResultSections
        :param output: The output from the PowerShellProfiler tool
        :param result: A Result object containing the service results
        :return: None
        """
        suspicious_res_sec = ResultSection("Suspicious Activity Detected")
        suspicious_res_sec.set_heuristic(3)
        suspicious_res_sec.add_lines(output["behaviour"]["tags"])
        if len(suspicious_res_sec.body) > 0:
            result.add_section(suspicious_res_sec)

    @staticmethod
    def _handle_psdecode_output(output: List[str], result: Result) -> None:
        """
        This method converts the output from the PSDecode tool into ResultSections
        :param output: The output from the PSDecode tool
        :param result: A Result object containing the service results
        :return: None
        """
        pass

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

    @staticmethod
    def get_id_from_data(file_path: str) -> str:
        """
        This method generates a sha256 hash for the file contents of a file
        :param file_path: The file path
        :return hash: The sha256 hash of the file
        """
        sha256_hash = sha256()
        # stream it in so we don't load the whole file in memory
        with open(file_path, 'rb') as f:
            data = f.read(4096)
            while data:
                sha256_hash.update(data)
                data = f.read(4096)
        return sha256_hash.hexdigest()
