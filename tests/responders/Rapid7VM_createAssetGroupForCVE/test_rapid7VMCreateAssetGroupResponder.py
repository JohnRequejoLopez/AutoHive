import unittest
from unittest.mock import patch, MagicMock
from responders.Rapid7VM_createAssetGroupForCVE.Rapid7VM_createAssetGroupForCVE import rapid7VMResponder

class TestRapid7Responder(unittest.TestCase):

    @patch('responders.Rapid7VM_createAssetGroupForCVE.Rapid7.vulnerabilityManagement')
    @patch('responders.Rapid7VM_createAssetGroupForCVE.thehive.TheHive')
    @patch('sys.stdin')
    def test_run_successful(self, mock_stdin, MockTheHive, MockVulnMgmt):
        import json

        input_data = {
            "config": {
                "userName": "dummy_userName",
                "password": "dummy_password",
                "instanceURL": "https://rapid7.local",
                "thehiveInstance": "https://thehive.local",
                "thehiveApiKey": "dummy_apiKey"
            },
            "data": {
                "data": "CVE-2025-TEST",
                "dataType": "cve",
                "_id": "observable123"
            },
            "dataType": "cve",
            "_id": "observable123"
            
        }

        mock_stdin.isatty.return_value = False
        mock_stdin.read.return_value = json.dumps(input_data)

        responder = rapid7VMResponder()

        responder.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.userName': 'dummy_userName',
            'config.password': 'dummy_password',
            'config.instanceURL': 'https://rapid7.local',
            'config.thehiveInstance': 'https://thehive.local',
            'config.thehiveApiKey': 'dummy_apiKey',
            "data": {
                "data": "CVE-2025-TEST",
                "dataType": "cve",
                "_id": "observable123"
            },
            "dataType": "cve",
            "_id": "observable123"
        }[x])

        # Mocking TheHive instance
        mock_hive_instance = MockTheHive.return_value
        mock_hive_instance.updateObservable.return_value = {}

        # Mocking Rapid7 vulnerabilityManagement instance
        mock_r7_instance = MockVulnMgmt.return_value
        mock_r7_instance.createAssetGroup.return_value = {"id": "group123"}
        mock_r7_instance.getAssetGroupByName.return_value = {"resources": [{"id": "group123"}]}

        responder.report = MagicMock()
        responder.run()

        responder.report.assert_called_once_with({
            "url": "https://rapid7.local/group.jsp?groupid=group123"
        })

    @patch('responders.Rapid7VM_createAssetGroupForCVE.Rapid7.vulnerabilityManagement')
    @patch('responders.Rapid7VM_createAssetGroupForCVE.thehive.TheHive')
    @patch('sys.stdin')
    def test_run_no_cve(self, mock_stdin, MockTheHive, MockVulnMgmt):
        import json

        input_data = {
            "config": {
                "userName": "dummy_userName",
                "password": "dummy_password",
                "instanceURL": "https://rapid7.local",
                "thehiveInstance": "https://thehive.local",
                "thehiveApiKey": "dummy_apiKey"
            },
            "data": {
                "data": "123",
                "dataType": "ip",
                "_id": "observable123"
            }
        }

        mock_stdin.isatty.return_value = False
        mock_stdin.read.return_value = json.dumps(input_data)

        responder = rapid7VMResponder()

        responder.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.userName': 'dummy_userName',
            'config.password': 'dummy_password',
            'config.instanceURL': 'https://rapid7.local',
            'config.thehiveInstance': 'https://thehive.local',
            'config.thehiveApiKey': 'dummy_apiKey',
            "data": {
                "data": "123",
                "dataType": "ip",
                "_id": "observable123"
            }
        }[x])

        mock_hive_instance = MockTheHive.return_value
        mock_hive_instance.getCaseObservable.return_value = []

        responder.error = MagicMock()
        responder.run()

        responder.error.assert_called_once_with("No CVE observable type was found in the case.")

if __name__ == '__main__':
    unittest.main()
