import os
import pytest
import shutil

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name='overpower',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
        safelist_config={
            "enabled": False,
            "hash_types": ['sha1', 'sha256'],
            "enforce_safelist_service": False
        }
    ),
]


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        result_heuristic_equality = this.heuristic.attack_ids == that.heuristic.attack_ids and \
            this.heuristic.frequency == that.heuristic.frequency and \
            this.heuristic.heur_id == that.heuristic.heur_id and \
            this.heuristic.score == that.heuristic.score and \
            this.heuristic.score_map == that.heuristic.score_map and \
            this.heuristic.signatures == that.heuristic.signatures

        if not result_heuristic_equality:
            print("The heuristics are not equal:")
            if this.heuristic.attack_ids != that.heuristic.attack_ids:
                print("The attack_ids are different:")
                print(f"{this.heuristic.attack_ids}")
                print(f"{that.heuristic.attack_ids}")
            if this.heuristic.frequency != that.heuristic.frequency:
                print("The frequencies are different:")
                print(f"{this.heuristic.frequency}")
                print(f"{that.heuristic.frequency}")
            if this.heuristic.heur_id != that.heuristic.heur_id:
                print("The heur_ids are different:")
                print(f"{this.heuristic.heur_id}")
                print(f"{that.heuristic.heur_id}")
            if this.heuristic.score != that.heuristic.score:
                print("The scores are different:")
                print(f"{this.heuristic.score}")
                print(f"{that.heuristic.score}")
            if this.heuristic.score_map != that.heuristic.score_map:
                print("The score_maps are different:")
                print(f"{this.heuristic.score_map}")
                print(f"{that.heuristic.score_map}")
            if this.heuristic.signatures != that.heuristic.signatures:
                print("The signatures are different:")
                print(f"{this.heuristic.signatures}")
                print(f"{that.heuristic.signatures}")

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        print("The heuristics are not equal:")
        if this.heuristic:
            print(f"{this.heuristic.__dict__}")
        else:
            print("this.heuristic is None")
        if that.heuristic:
            print(f"{that.heuristic.__dict__}")
        else:
            print("that.heuristic is None")
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
        this.body == that.body and \
        this.body_format == that.body_format and \
        this.classification == that.classification and \
        this.depth == that.depth and \
        len(this.subsections) == len(that.subsections) and \
        this.title_text == that.title_text and \
        this.tags == that.tags and \
        this.auto_collapse == that.auto_collapse

    if not current_section_equality:
        print("The current sections are not equal:")
        if not result_heuristic_equality:
            print("The result heuristics are not equal")
        if this.body != that.body:
            print("The bodies are different:")
            print(f"{this.body}")
            print(f"{that.body}")
        if this.body_format != that.body_format:
            print("The body formats are different:")
            print(f"{this.body_format}")
            print(f"{that.body_format}")
        if this.classification != that.classification:
            print("The classifications are different:")
            print(f"{this.classifications}")
            print(f"{that.classifications}")
        if this.depth != that.depth:
            print("The depths are different:")
            print(f"{this.depths}")
            print(f"{that.depths}")
        if len(this.subsections) != len(that.subsections):
            print("The number of subsections are different:")
            print(f"{len(this.subsections)}")
            print(f"{len(that.subsections)}")
        if this.title_text != that.title_text:
            print("The title texts are different:")
            print(f"{this.title_text}")
            print(f"{that.title_text}")
        if this.tags != that.tags:
            print("The tags are different:")
            print(f"{this.tags}")
            print(f"{that.tags}")
        if this.auto_collapse != that.auto_collapse:
            print("The auto_collapse settings are different:")
            print(f"{this.auto_collapse}")
            print(f"{that.auto_collapse}")
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def overpower_class_instance():
    create_tmp_manifest()
    try:
        from overpower import Overpower
        yield Overpower()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_completed_process_instance():
    class DummyCompletedProcess:
        def __init__(self):
            self.stdout = b"blah\nblah"

        def __enter__(self, *args, **kwargs):
            pass

        def __exit__(self, *args, **kwargs):
            return self

    yield DummyCompletedProcess()


class TestOverpower:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(overpower_class_instance):
        assert overpower_class_instance.artifact_hashes is None
        assert overpower_class_instance.artifact_list is None

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, overpower_class_instance, dummy_completed_process_instance, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from assemblyline_v4_service.common.dynamic_service_helper import OntologyResults
        from subprocess import TimeoutExpired

        mocker.patch("overpower.profile_ps1", return_value=[])
        mocker.patch.object(overpower_class_instance, "_handle_ps1_profiler_output")
        mocker.patch.object(overpower_class_instance, "_handle_psdecode_output")
        mocker.patch.object(overpower_class_instance, "_extract_supplementary")
        mocker.patch.object(overpower_class_instance, "_prepare_artifacts")
        mocker.patch("overpower.Popen", return_value=dummy_completed_process_instance)
        mocker.patch.object(OntologyResults, "handle_artifacts")

        service_task = ServiceTask(sample)
        task = Task(service_task)
        task.service_config = {
            "tool_timeout": 60,
            "add_supplementary": True,
        }
        overpower_class_instance._task = task
        service_request = ServiceRequest(task)

        # Actually executing the sample
        overpower_class_instance.execute(service_request)
        assert overpower_class_instance.artifact_list == []

        # Code coverage
        mocker.patch("overpower.Popen", side_effect=TimeoutExpired("blah", 1))
        overpower_class_instance.execute(service_request)

        if os.path.exists(overpower_class_instance.working_directory):
            shutil.rmtree(overpower_class_instance.working_directory)

    @staticmethod
    def test_handle_ps1_profiler_output(overpower_class_instance):
        from os import path
        from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection, TableRow
        output = {
            "deobfuscated": "blah", "behaviour": {"blah": {"score": 2.0, "marks": []}},
            "score": 3, "families": {},
            "extracted": []}
        res = Result()
        correct_res_sec = ResultSection("Suspicious Content Detected in blah")
        correct_sig_res_sec = ResultSection("Signature: blah", parent=correct_res_sec)
        correct_sig_res_sec.set_heuristic(3)
        correct_sig_res_sec.heuristic.add_signature_id("blah", score=100)
        overpower_class_instance._handle_ps1_profiler_output(output, res, "blah")
        assert check_section_equality(res.sections[0], correct_res_sec)

        output["behaviour"]["minus"] = {"score": -1, "marks": []}
        output["families"] = {"blah": {"regex_indicators": ["blah"], "str_indicators": ["blah"]}}
        output["deobfuscated"] = "http://blah.com/blah.exe"
        correct_res_sec = ResultSection("Malicious Content Detected in blah")
        correct_res_sec.set_heuristic(2)
        correct_res_sec.add_tag("attribution.family", "blah")
        correct_res_sec.add_line("Attribution family: blah")
        correct_res_sec.add_line("\tMatched regular expressions:")
        correct_res_sec.add_line("\t\tblah")
        correct_res_sec.add_line("\tMatched any or all strings:")
        correct_res_sec.add_line("\t\tblah")
        overpower_class_instance._handle_ps1_profiler_output(output, res, "blah")
        assert check_section_equality(res.sections[1], correct_res_sec)

        correct_ioc_res_sec = ResultTableSection("IOC(s) extracted from blah")
        correct_ioc_res_sec.add_tag("network.dynamic.domain", "blah.com")
        correct_ioc_res_sec.add_tag("network.dynamic.uri", "http://blah.com/blah.exe")
        correct_ioc_res_sec.add_tag("network.dynamic.uri_path", "/blah.exe")
        correct_ioc_res_sec.set_heuristic(1)
        table_data = [{"ioc_type": "domain", "ioc": "blah.com"},
                      {"ioc_type": "uri", "ioc": "http://blah.com/blah.exe"},
                      {"ioc_type": "uri_path", "ioc": "/blah.exe"}]
        for item in table_data:
            correct_ioc_res_sec.add_row(TableRow(**item))
        assert check_section_equality(res.sections[2], correct_ioc_res_sec)

        output = {"deobfuscated": "blah.com;", "behaviour": {"blah": {"score": 2.0, "marks": []}},
                  "score": 3, "families": [], "extracted": [{"type": "base64_decoded", "data": b"blah"}]}
        overpower_class_instance._handle_ps1_profiler_output(output, res, "blah")
        assert len(res.sections) == 3
        assert not path.exists(path.join(overpower_class_instance.working_directory, "ps1profiler_base64_decoded_0"))

        if os.path.exists(overpower_class_instance.working_directory):
            shutil.rmtree(overpower_class_instance.working_directory)

    @staticmethod
    def test_handle_psdecode_output(overpower_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection, TableRow
        res = Result()
        correct_res_sec = ResultSection("Actions detected with PSDecode")
        output = ["blah", "############################## Actions ##############################", "blah.com"]
        correct_res_sec.set_body("blah.com")
        actions_ioc_table = ResultTableSection("IOCs found in actions", parent=correct_res_sec)
        table_data = [{"ioc_type": "domain", "ioc": "blah.com"}]
        for item in table_data:
            actions_ioc_table.add_row(TableRow(**item))
        actions_ioc_table.add_tag("network.dynamic.domain", "blah.com")
        actions_ioc_table.set_heuristic(1)
        overpower_class_instance._handle_psdecode_output(output, res)
        assert check_section_equality(res.sections[0], correct_res_sec)

    @staticmethod
    def test_extract_supplementary(overpower_class_instance):
        from os import path
        from json import dumps
        ps1_profiler_output = {"blah": "blah"}
        psdecode_output = ["blah"]
        suppl_ps1_profiler_output = path.join(
            overpower_class_instance.working_directory, "suppl_ps1_profiler_output.json")
        suppl_psdecode_output = path.join(overpower_class_instance.working_directory, "suppl_psdecode_output.txt")
        overpower_class_instance._extract_supplementary(ps1_profiler_output, psdecode_output)
        assert path.exists(suppl_ps1_profiler_output)
        assert path.exists(suppl_psdecode_output)
        with open(suppl_ps1_profiler_output, "r") as f:
            assert f.read() == dumps(ps1_profiler_output)
        with open(suppl_psdecode_output, "r") as f:
            assert f.read() == "blah"

        if os.path.exists(overpower_class_instance.working_directory):
            shutil.rmtree(overpower_class_instance.working_directory)

    @staticmethod
    def test_prepare_artifacts(overpower_class_instance):
        from os.path import join
        from tools.ps1_profiler import DEOBFUS_FILE
        overpower_class_instance.artifact_list = []
        overpower_class_instance.artifact_hashes = set()

        item_0 = join(overpower_class_instance.working_directory, DEOBFUS_FILE)
        item_1 = join(overpower_class_instance.working_directory, "layer1.txt")
        item_2 = join(overpower_class_instance.working_directory, "suppl")
        item_3 = join(overpower_class_instance.working_directory, "executable.bin")
        items = [item_0, item_1, item_2, item_3]
        for index, item in enumerate(items):
            with open(item, "w") as f:
                f.write(f"blah_{index}")

        item_4 = join(overpower_class_instance.working_directory, "suppl_duplicate")
        with open(item_4, "w") as f:
            f.write("blah_2")

        overpower_class_instance._prepare_artifacts()
        assert overpower_class_instance.artifact_list[0] == {
            "name": DEOBFUS_FILE,
            "path": item_0,
            "description": "De-obfuscated file from PowerShellProfiler",
            "to_be_extracted": True,
            "sha256": "e388fc2e014ed2d7a269f5936e825dc19797a979d64aa9e9408dadb80ea9d82e",
        }
        assert overpower_class_instance.artifact_list[1] == {
            "name": "executable.bin",
            "path": item_3,
            "description": "Overpower Dump",
            "to_be_extracted": True,
            "sha256": "96098ae905117093937447807ca60b2d1105df9f35163f2a0f2bb6ed7c58e2d9",
        }
        assert overpower_class_instance.artifact_list[2] == {
            "name": "layer1.txt",
            "path": item_1,
            "description": "Layer of de-obfuscated PowerShell from PSDecode",
            "to_be_extracted": True,
            "sha256": "823b42df5b53e54895e9f8a0dd7430c722c63796fb847db2a43cde91bc951a38",
        }
        assert overpower_class_instance.artifact_list[3] == {
            "name": "2d0bc6e82ff7dda5491eefc888ea9fae386f8460bf461fa763944149d0cd8caa",
            "path": item_2,
            "description": "Output from PowerShell tool",
            "to_be_extracted": False,
            "sha256": "2d0bc6e82ff7dda5491eefc888ea9fae386f8460bf461fa763944149d0cd8caa",
        }

        overpower_class_instance.artifact_list = []
        overpower_class_instance.artifact_hashes = set()
        overpower_class_instance._prepare_artifacts(False)
        assert overpower_class_instance.artifact_list[0] == {
            "name": "2d0bc6e82ff7dda5491eefc888ea9fae386f8460bf461fa763944149d0cd8caa",
            "path": item_2,
            "description": "Output from PowerShell tool",
            "to_be_extracted": False,
            "sha256": "2d0bc6e82ff7dda5491eefc888ea9fae386f8460bf461fa763944149d0cd8caa",
        }

        if os.path.exists(overpower_class_instance.working_directory):
            shutil.rmtree(overpower_class_instance.working_directory)
