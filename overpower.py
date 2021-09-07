from typing import Optional, Dict, Any

from subprocess import run, TimeoutExpired
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT, Heuristic

from tools.ps1_profiler import main as ps1_profiler


class Overpower(ServiceBase):

    def __init__(self, config) -> None:
        super().__init__()

    def start(self) -> None:
        pass

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()

        output = ps1_profiler(request.file_path, debug=True)
        print(output)

        # PSDecode
        # psz = sz = None
        # sz = request.file_contents.decode()
        # try:
        #     fRecurse = True
        #     while fRecurse:
        #         psz = str(sz)
        #         sz2 = psx.xray(sz)
        #         if len(sz2) == 0:
        #             fRecurse = False
        #             print(psz)
        #         sz = sz2
        # except:
        #     print(psz)
        #     pass

        # PyPowerShellXray
        # args = ["python", "./pypowershellxray/psx.py", "-f", request.file_path, "--verbose", "--dumpapis", "--apidb", "./pypowershellxray/apihashes.db"]
        # try:
        #     completed_process = run(args=args, capture_output=True, timeout=60)
        # except TimeoutExpired:
        #     completed_process = None
        #
        # ps1_xray_output = []
        # if completed_process:
        #     ps1_xray_output = completed_process.stdout.decode().split("\n")
        #
        print("here")


