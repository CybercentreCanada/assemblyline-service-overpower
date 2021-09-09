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
    ),
]


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        heuristic_equality = this.heuristic.definition.attack_id == that.heuristic.definition.attack_id and \
                             this.heuristic.definition.classification == that.heuristic.definition.classification and \
                             this.heuristic.definition.description == that.heuristic.definition.description and \
                             this.heuristic.definition.filetype == that.heuristic.definition.filetype and \
                             this.heuristic.definition.heur_id == that.heuristic.definition.heur_id and \
                             this.heuristic.definition.id == that.heuristic.definition.id and \
                             this.heuristic.definition.max_score == that.heuristic.definition.max_score and \
                             this.heuristic.definition.name == that.heuristic.definition.name and \
                             this.heuristic.definition.score == that.heuristic.definition.score and \
                             this.heuristic.definition.signature_score_map == \
                             that.heuristic.definition.signature_score_map

        result_heuristic_equality = heuristic_equality and \
                                    this.heuristic.attack_ids == that.heuristic.attack_ids and \
                                    this.heuristic.frequency == that.heuristic.frequency and \
                                    this.heuristic.heur_id == that.heuristic.heur_id and \
                                    this.heuristic.score == that.heuristic.score and \
                                    this.heuristic.score_map == that.heuristic.score_map and \
                                    this.heuristic.signatures == that.heuristic.signatures

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
                               this.body == that.body and \
                               this.body_format == that.body_format and \
                               this.classification == that.classification and \
                               this.depth == that.depth and \
                               len(this.subsections) == len(that.subsections) and \
                               this.title_text == that.title_text and \
                               this.tags == that.tags

    if not current_section_equality:
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
        from assemblyline_v4_service.common.result import Result
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from tools import ps1_profiler
        from json import loads
        from os import path, mkdir
        from subprocess import TimeoutExpired

        mocker.patch("overpower.profile_ps1", return_value=[])
        mocker.patch.object(overpower_class_instance, "_handle_ps1_profiler_output")
        mocker.patch.object(overpower_class_instance, "_handle_psdecode_output")
        mocker.patch.object(overpower_class_instance, "_extract_supplementary")
        mocker.patch.object(overpower_class_instance, "_prepare_artifacts")
        mocker.patch("overpower.run", return_value=dummy_completed_process_instance)
        mocker.patch.object(SandboxOntology, "handle_artifacts")

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

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding unique items in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the service_completed and the output.json supplementary
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        correct_result_response.pop("supplementary")
        test_result_response.pop("supplementary")
        correct_result_response.pop("service_context")
        test_result_response.pop("service_context")
        assert test_result_response == correct_result_response

        # Code coverage
        mocker.patch("overpower.run", side_effect=TimeoutExpired("blah", 1))
        overpower_class_instance.execute(service_request)

    @staticmethod
    def test_handle_ps1_profiler_output(overpower_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection
        output = {"behaviour": {"tags": ["blah"]}, "score": 3}
        res = Result()
        correct_res_sec = ResultSection("Suspicious Activity Detected", body="blah")
        correct_res_sec.set_heuristic(3)
        overpower_class_instance._handle_ps1_profiler_output(output, res)
        assert check_section_equality(res.sections[0], correct_res_sec)

        output["score"] = 6
        correct_res_sec.heuristic = None
        correct_res_sec.set_heuristic(4)
        overpower_class_instance._handle_ps1_profiler_output(output, res)
        assert check_section_equality(res.sections[1], correct_res_sec)

    @staticmethod
    def test_handle_psdecode_output(overpower_class_instance):
        from assemblyline_v4_service.common.result import Result
        res = Result()
        output = []
        overpower_class_instance._handle_psdecode_output(output, res)
        assert True

    @staticmethod
    def test_extract_supplementary(overpower_class_instance):
        from os import path
        from json import dumps
        ps1_profiler_output = {"blah": "blah"}
        psdecode_output = ["blah"]
        suppl_ps1_profiler_output = path.join(overpower_class_instance.working_directory, "suppl_ps1_profiler_output.json")
        suppl_psdecode_output = path.join(overpower_class_instance.working_directory, "suppl_psdecode_output.txt")
        overpower_class_instance._extract_supplementary(ps1_profiler_output, psdecode_output)
        assert path.exists(suppl_ps1_profiler_output)
        assert path.exists(suppl_psdecode_output)
        with open(suppl_ps1_profiler_output, "r") as f:
            assert f.read() == dumps(ps1_profiler_output)
        with open(suppl_psdecode_output, "r") as f:
            assert f.read() == "blah"

    @staticmethod
    def test_prepare_artifacts(overpower_class_instance):
        from os.path import join
        from tools.ps1_profiler import DEOBFUS_FILE
        overpower_class_instance.artifact_list = []
        overpower_class_instance.artifact_hashes = set()

        item_0 = join(overpower_class_instance.working_directory, DEOBFUS_FILE)
        item_1 = join(overpower_class_instance.working_directory, "layer1.txt")
        item_2 = join(overpower_class_instance.working_directory, "suppl")
        items = [item_0, item_1, item_2]
        for index, item in enumerate(items):
            with open(item, "w") as f:
                f.write(f"blah_{index}")

        item_3 = join(overpower_class_instance.working_directory, "suppl_duplicate")
        with open(item_3, "w") as f:
            f.write("blah_2")

        item_4 = join(overpower_class_instance.working_directory, "random_dump")
        with open(item_4, "w") as f:
            f.write("yaba")

        overpower_class_instance._prepare_artifacts()
        assert overpower_class_instance.artifact_list[0] == {
            "name": DEOBFUS_FILE,
            "path": item_0,
            "description": "De-obfuscated file from PowerShellProfiler",
            "to_be_extracted": True
        }
        assert overpower_class_instance.artifact_list[1] == {
            "name": "layer1.txt",
            "path": item_1,
            "description": "Layer of de-obfuscated PowerShell from PSDecode",
            "to_be_extracted": True
        }
        assert overpower_class_instance.artifact_list[2] == {
            "name": "suppl",
            "path": item_2,
            "description": "Output from PowerShell tool",
            "to_be_extracted": False
        }

    @staticmethod
    @pytest.mark.parametrize("data, expected_result", [
        (b"blah", '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52')
    ])
    def test_get_id_from_data(data, expected_result):
        from os import remove
        from overpower import get_id_from_data
        some_file = "some_file.txt"
        with open(some_file, "wb") as f:
            f.write(b"blah")
        assert get_id_from_data(some_file) == expected_result
        remove(some_file)
