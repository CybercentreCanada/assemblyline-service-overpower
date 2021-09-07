import hashlib
import random
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin
import json
from requests import Session, Response, ConnectionError, exceptions, codes

from assemblyline.common.exceptions import RecoverableError
from assemblyline.common.isotime import iso_to_local, iso_to_epoch, epoch_to_local, now, now_as_local
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT, Heuristic


class AvHitSection(ResultSection):
    def __init__(self, av_name: str, virus_name: str, engine: Dict[str, str], heur_id: int,
                 sig_score_revision_map: Dict[str, int], kw_score_revision_map: Dict[str, int],
                 safelist_match: List[str]) -> None:
        title = f"{av_name} identified the file as {virus_name}"
        json_body = dict(
            av_name=av_name,
            virus_name=virus_name,
            scan_result="infected" if heur_id == 1 else "suspicious",
            engine_version=engine['version'] if engine else "unknown",
            engine_definition_time=engine['def_time'] if engine else "unknown",
        )

        super(AvHitSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body),
            classification=Classification.UNRESTRICTED,
        )
        signature_name = f'{av_name}.{virus_name}'
        section_heur = Heuristic(heur_id)
        if signature_name in sig_score_revision_map:
            section_heur.add_signature_id(signature_name, sig_score_revision_map[signature_name])
        elif any(kw in signature_name.lower() for kw in kw_score_revision_map):
            section_heur.add_signature_id(
                signature_name,
                max([kw_score_revision_map[kw] for kw in kw_score_revision_map if kw in signature_name.lower()])
            )
        elif virus_name in safelist_match:
            section_heur.add_signature_id(signature_name, score=0)
        else:
            section_heur.add_signature_id(signature_name)
        self.heuristic = section_heur
        self.add_tag('av.virus_name', virus_name)


class AvErrorSection(ResultSection):
    def __init__(self, av_name: str, engine: Dict[str, str]) -> None:
        title = f"{av_name} failed to scan the file"
        body = f"Engine: {engine['version']} :: Definition: {engine['def_time']}" if engine else ""
        super(AvErrorSection, self).__init__(
            title_text=title,
            body=body,
            classification=Classification.UNRESTRICTED
        )


class MetaDefender(ServiceBase):
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super(MetaDefender, self).__init__(config)
        self.session: Optional[Session] = None
        self.timeout = self.config.get("md_timeout", (40*2)/3)
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.current_node: Optional[str] = None
        self.start_time: Optional[float] = None
        self.headers: Optional[Dict[str, str]] = None
        self.blocklist: Optional[List[str]] = None
        self.kw_score_revision_map: Optional[Dict[str, int]] = None
        self.sig_score_revision_map: Optional[Dict[str, Any]] = None
        self.safelist_match: List[str] = []
        api_key = self.config.get("api_key")
        if api_key:
            self.headers = {"apikey": api_key}

        try:
            safelist = self.get_api_interface().get_safelist(["av.virus_name"])
            [self.safelist_match.extend(match_list) for _, match_list in safelist.get('match', {}).items()]
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")

    def start(self) -> None:
        self.log.debug("MetaDefender service started")
        base_urls: List[str] = []
        if type(self.config.get("base_url")) == str:
            base_urls = [self.config.get("base_url")]
        elif type(self.config.get("base_url")) == list:
            for base_url in self.config.get("base_url"):
                prepared_base_url = base_url.replace(" ", "")
                base_urls.append(prepared_base_url)
        else:
            raise Exception("Invalid format for BASE_URL service variable (must be str or list)")
        av_config: Dict[str, Any] = self.config.get("av_config", {})
        self.blocklist: List[str] = av_config.get("blocklist", [])
        self.kw_score_revision_map: Dict[str, int] = av_config.get("kw_score_revision_map", {})
        self.sig_score_revision_map: Dict[str, int] = av_config.get("sig_score_revision_map", {})

        # Initialize a list of all nodes with default data
        for index, url in enumerate(base_urls):
            self.nodes[url] = {'engine_map': {},
                               'engine_count': 0,
                               'engine_list': "default",
                               'newest_dat': epoch_to_local(0),
                               'oldest_dat': now_as_local(),
                               'file_count': 0,
                               'queue_times': [],
                               'average_queue_time': 0
                               }

        # Get version map for all of the nodes
        self.session = Session()
        engine_count = 0
        for node in list(self.nodes.keys()):
            try:
                self._get_version_map(node)
            except Exception as e:
                self.log.error(f"Unable to contact {node} due to {e}. Removing from node list.")
                del self.nodes[node]
                continue
            engine_count += self.nodes[node]['engine_count']

        if len(list(self.nodes.keys())) == 0:
            raise Exception("All MetaDefender Core nodes are down. Please ensure that the URLs are correct in the "
                            "service config and that the MetaDefender Core REST API is running at each one.")

        if engine_count == 0:
            raise Exception(f"MetaDefender Core nodes {list(self.nodes.keys())} have an active engine_count of 0")

        # On first launch, choose random node to start with
        if not self.current_node:
            while True:
                self.current_node = random.choice(list(self.nodes.keys()))

                # Check to see if the chosen node has a version map, else try to get version map again
                if self.nodes[self.current_node]['engine_count'] >= 1:
                    self.log.info(f"Node ({self.current_node}) chosen at launch")
                    break
                else:
                    self._get_version_map(self.current_node)

        # Start the global timer
        if not self.start_time:
            self.start_time = time.time()

    @staticmethod
    def _format_engine_name(name: str) -> str:
        """
        This method formats the engine name so that it is nicer to parse/print
        :param name: The engine name to format
        :return: The formated engine name
        """
        new_name = name.lower().replace(" ", "").replace("!", "")
        if new_name.endswith("av"):
            new_name = new_name[:-2]
        return new_name

    def _get_version_map(self, node: str) -> None:
        """
        Get the versions of all engines running on a given node
        :param node: The IP of the MetaDefender node
        :return: None
        """
        newest_dat = 0
        oldest_dat = now()
        engine_list = []
        active_engines = 0
        failed_states = ["removed", "temporary failed", "permanently failed"]
        url = urljoin(node, 'stat/engines')

        try:
            self.log.debug(f"_get_version_map: GET {url}")
            r = self.session.get(url=url, timeout=self.timeout)
            engines = r.json()

            for engine in engines:
                if engine['active'] and engine["state"] not in failed_states:
                    active_engines += 1

                if self.config.get("md_version") == 4:
                    name = self._format_engine_name(engine["eng_name"])
                    version = engine['eng_ver']
                    def_time = engine['def_time']
                    etype = engine['engine_type']
                elif self.config.get("md_version") == 3:
                    name = self._format_engine_name(engine["eng_name"]).replace("scanengine", "")
                    version = engine['eng_ver']
                    def_time = engine['def_time'].replace(" AM", "").replace(" PM", "").replace("/", "-").replace(" ",
                                                                                                                  "T")
                    def_time = def_time[6:10] + "-" + def_time[:5] + def_time[10:] + "Z"
                    etype = engine['eng_type']
                else:
                    raise Exception("Unknown version of MetaDefender")

                # Compute newest DAT
                dat_epoch = iso_to_epoch(def_time)
                if dat_epoch > newest_dat:
                    newest_dat = dat_epoch

                if dat_epoch < oldest_dat and dat_epoch != 0 and etype in ["av", "Bundled engine"]:
                    oldest_dat = dat_epoch

                self.nodes[node]['engine_map'][name] = {
                    'version': version,
                    'def_time': iso_to_local(def_time)[:19]
                }
                engine_list.append(name)
                engine_list.append(version)
                engine_list.append(def_time)

            self.nodes[node]['engine_count'] = active_engines
            self.nodes[node]['newest_dat'] = epoch_to_local(newest_dat)[:19]
            self.nodes[node]['oldest_dat'] = epoch_to_local(oldest_dat)[:19]
            self.nodes[node]['engine_list'] = "".join(engine_list)
        except exceptions.Timeout:
            raise Exception(f"Node ({node}) timed out after {self.timeout}s while trying to get engine version map")
        except ConnectionError:
            raise Exception(f"Unable to connect to node ({node}) while trying to get engine version map")

    def get_tool_version(self) -> str:
        """
        This method generates an MD5 hash of all engines for all nodes
        :return: The MD5 hash of all engine lists
        """
        engine_lists = ""
        for node in list(self.nodes.keys()):
            engine_lists += self.nodes[node]['engine_list']
        return hashlib.md5(engine_lists.encode('utf-8')).hexdigest()

    def execute(self, request: ServiceRequest) -> None:
        # Check that the current node has a version map
        while True:
            if self.nodes[self.current_node]['engine_count'] == 0:
                self._get_version_map(self.current_node)
                self.log.info("Getting version map from execute() function")
                if self.nodes[self.current_node]['engine_count'] == 0:
                    self.new_node(force=True)
            else:
                break

        filename = request.file_path
        try:
            response = self.scan_file(filename)
        except RecoverableError:
            response = self.scan_file(filename)
        result = self.parse_results(response)
        request.result = result
        request.set_service_context(f"Definition Time Range: {self.nodes[self.current_node]['oldest_dat']} - "
                                    f"{self.nodes[self.current_node]['newest_dat']}")

        # Compare queue time of current node with new random node after a minimum run time on current node
        elapsed_time = time.time() - self.start_time
        if elapsed_time >= self.config.get("max_node_time"):
            self.new_node(force=True)
        elif elapsed_time >= self.config.get("min_node_time"):
            self.new_node(force=False)

    def get_scan_results_by_data_id(self, data_id: str) -> Response:
        """
        This method gets the results from MetaDefender regarding the scanned file
        :param data_id: The ID of the submission according to MetaDefender
        :return: The response from the REST API
        """
        url = urljoin(self.current_node, f"file/{data_id}")

        try:
            self.log.debug(f"get_scan_results_by_data_id: GET {url}")
            return self.session.get(url=url, headers=self.headers, timeout=self.timeout)
        except exceptions.Timeout:
            self.new_node(force=True, reset_queue=True)
            raise Exception(f"Node ({self.current_node}) timed out after {self.timeout}s "
                            "while trying to fetch scan results")
        except ConnectionError:
            # MetaDefender inaccessible
            self.new_node(force=True, reset_queue=True)
            raise RecoverableError(f"Unable to reach node ({self.current_node}) while trying to fetch scan results")

    def new_node(self, force: bool, reset_queue: bool = False) -> None:
        """
        This is method chooses a new node based on a series of factors
        :param force: Force a new node to be used
        :param reset_queue: Reset the average time a file sits in a queue
        :return: None
        """
        if len(self.nodes) == 1:
            time.sleep(5)
            return

        self.session.close()

        if self.nodes[self.current_node]['file_count'] > 1:
            average = sum(self.nodes[self.current_node]['queue_times']) / self.nodes[self.current_node]['file_count']

            # Reset the average queue time, when connection or timeout error
            if reset_queue:
                self.nodes[self.current_node]['average_queue_time'] = 0
            else:
                self.nodes[self.current_node]['average_queue_time'] = average
            self.nodes[self.current_node]['file_count'] = 0

            while True:
                temp_node = random.choice(list(self.nodes.keys()))
                if temp_node != self.current_node:
                    if force:
                        self.log.info(f"Changed node from {self.current_node} to {temp_node}")
                        self.current_node = temp_node
                        self.start_time = time.time()
                        return
                    else:
                        # Only change to new node if the current node's average queue time is larger than the new node
                        if average > self.nodes[temp_node]['average_queue_time']:
                            self.log.info(f"Changed node from {self.current_node} to {temp_node}")
                            self.current_node = temp_node

                        # Reset the start time
                        self.start_time = time.time()
                        return

    def scan_file(self, filename: str) -> Dict[str, Any]:
        """
        This method POSTs the file to the MetaDefender REST API
        :param filename: The name of the file to be submitted to MetaDefender
        :return: The JSON response of the scan results
        """
        # Let's scan the file
        url = urljoin(self.current_node, 'file')
        with open(filename, 'rb') as f:
            data = f.read()

        try:
            self.log.debug(f"scan_file: POST {url}")
            r = self.session.post(url=url, data=data, headers=self.headers, timeout=self.timeout)
        except exceptions.Timeout:
            self.new_node(force=True, reset_queue=True)
            raise Exception(f"Node ({self.current_node}) timed out after {self.timeout}s "
                            "while trying to send file for scanning")
        except ConnectionError:
            # MetaDefender inaccessible
            self.new_node(force=True, reset_queue=True)  # Deactivate the current node which had a connection error
            raise RecoverableError(
                f"Unable to reach node ({self.current_node}) while trying to send file for scanning")

        if r.status_code == codes.ok:
            data_id = r.json()['data_id']
            # Give MD some time to scan it!
            time.sleep(1)
            while True:
                r = self.get_scan_results_by_data_id(data_id=data_id)
                if r.status_code != codes.ok:
                    return r.json()
                try:
                    if r.json()['scan_results']['progress_percentage'] == 100:
                        break
                    else:
                        time.sleep(0.5)
                except KeyError:
                    # MetaDefender inaccessible
                    self.new_node(force=True, reset_queue=True)
                    raise RecoverableError(
                        f"Unable to reach node ({self.current_node}) while trying to fetch scan results")

            self.nodes[self.current_node]['timeout_count'] = 0
            self.nodes[self.current_node]['timeout'] = 0
        else:
            raise Exception(f"Unable to scan file due to {r.json()['err']}")
        return r.json()

    def parse_results(self, response: Dict[str, Any]) -> Result:
        """
        This method parses the response JSON containing the scan results so that it will be displayed nicely in
        Assemblyline
        :param response: The raw results from the MetaDefender scan
        :return: The Result object to be used when displaying in Assemblyline
        """
        res = Result()
        scan_results = response.get('scan_results', response)
        virus_name = ""
        process_results = response.get('process_info', response)
        hit = False
        fail = False
        processed = {}
        if scan_results is not None and scan_results.get('progress_percentage') == 100:
            no_threat_detected = []
            av_hits = ResultSection('AV Detections as Infected or Suspicious')
            av_fails = ResultSection('Failed to Scan or No Threats Detected')

            scans = scan_results.get('scan_details', scan_results)
            av_scan_times = []
            modified_scans = {key: value for key, value in scans.items() if key not in ["progress_percentage"]}
            for majorkey, subdict in sorted(modified_scans.items()):
                if majorkey in self.blocklist:
                    continue
                heur_id = None
                if subdict['scan_result_i'] == 1:           # File is infected
                    virus_name = subdict['threat_found']
                    if virus_name:
                        heur_id = 1
                elif subdict['scan_result_i'] == 2:         # File is suspicious
                    virus_name = subdict['threat_found']
                    if virus_name:
                        heur_id = 2
                elif subdict['scan_result_i'] == 10 or subdict['scan_result_i'] == 3:   # File was not scanned or failed
                    # noinspection PyBroadException
                    try:
                        engine = self.nodes[self.current_node]['engine_map'][self._format_engine_name(majorkey)]
                    except Exception:
                        engine = None
                    fail = True
                    av_fails.add_subsection(AvErrorSection(majorkey, engine))
                elif subdict['scan_result_i'] == 0:  # No threat detected
                    no_threat_detected.append(majorkey)
                    fail = True

                if heur_id is not None:
                    virus_name = virus_name.replace("a variant of ", "")
                    engine = self.nodes[self.current_node]['engine_map'][self._format_engine_name(majorkey)]
                    av_hit_section = AvHitSection(majorkey, virus_name, engine, heur_id,
                                                  self.sig_score_revision_map, self.kw_score_revision_map,
                                                  self.safelist_match)
                    av_hits.add_subsection(av_hit_section)
                    hit = True

                av_scan_times.append(self._format_engine_name(majorkey))
                av_scan_times.append(subdict['scan_time'])

            if hit:
                res.add_section(av_hits)

            # Only creat a result section for "No Threat Detected" if there was at least one hit
            if hit and fail:
                if no_threat_detected:
                    ResultSection("No Threat Detected by AV Engine(s)",
                                  body_format=BODY_FORMAT.KEY_VALUE,
                                  body=json.dumps(dict(no_threat_detected=no_threat_detected)),
                                  parent=av_fails)

                res.add_section(av_fails)

            file_size = response['file_info']['file_size']
            queue_time = response['process_info']['queue_time']
            processing_time = response['process_info']['processing_time']
            self.log.info(f"File successfully scanned by node ({self.current_node}). File size: {file_size} B."
                          f"Queue time: {queue_time} ms. Processing time: {processing_time} ms. "
                          f"AV scan times: {str(av_scan_times)}")

            # Add the queue time to a list, which will be later used to calculate average queue time
            self.nodes[self.current_node]['queue_times'].append(queue_time)
            self.nodes[self.current_node]['file_count'] += 1
        if process_results is not None and process_results.get('progress_percentage') == 100:
            hit = False
            fail = False
            processed = process_results.get('post_processing', process_results)
            if processed['actions_failed']:
                fail = True
            elif processed['actions_ran']:
                hit = True
        #add cdr json extracted
        if hit:
            cdr_json_section = ResultSection('CDR Successfully Executed', body_format=BODY_FORMAT.JSON,
                                             body=json.dumps(processed))
            res.add_section(cdr_json_section)
        if fail:
            cdr_fails = ResultSection('CDR Failed or No Malicious Files Found')
            res.add_section(cdr_fails)

        return res
