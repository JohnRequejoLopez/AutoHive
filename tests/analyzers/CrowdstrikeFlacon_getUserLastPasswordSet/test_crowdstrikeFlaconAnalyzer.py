import unittest
from unittest.mock import patch, MagicMock, mock_open
from analyzers.CrowdstrikeFalcon_getUserLastPasswordSet.falconComplete_getUserLastPasswordSet import crowdstrikeAnalyzer


class testCrowdstrikeAnalyzer(unittest.TestCase):
    
    @patch('analyzers.CrowdstrikeFalcon_getUserLastPasswordSet.crwd.CrowdStrikeModule')
    @patch('sys.stdin')
    def test_run_successful(self, mock_stdin, MockCrowdStrikeModule):
        import json

        input_data = {
            "config": {
                "clientId": "dummy_clientId",
                "clientSecret": "dummy_clientSecret",
                "targetHostName": "hostname1",
                "outputFile": "C:\\\\tmp\\\\file.txt"
            },
            "data": "testuser"
        }

        # Simula stdin con isatty y read()
        mock_stdin.isatty.return_value = False
        mock_stdin.read.return_value = json.dumps(input_data)

        analyzer = crowdstrikeAnalyzer()

        analyzer.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.clientId': 'dummy_clientId',
            'config.clientSecret': 'dummy_clientSecret',
            'config.targetHostName': 'hostname1',
            'config.outputFile': 'C:\\\\tmp\\\\file.txt',
            'data': 'testuser'
        }[x])

        mock_instance = MockCrowdStrikeModule.return_value
        mock_instance.runCloudScript.return_value = None
        mock_instance.getFileContent.return_value = ('{"password_last_set": "2025-04-09"}', '')
        mock_instance.deleteTmpFile.return_value = None
        mock_instance.close_rtr_session.return_value = None

        analyzer.report = MagicMock()
        analyzer.data_type = "username"
        analyzer.run()

        analyzer.report.assert_called_once_with({
            'summary': {
                'username': 'testuser',
                'LastPasswordSet': '2025-04-09'
            }
        })

    @patch('analyzers.CrowdstrikeFalcon_getUserLastPasswordSet.crwd.CrowdStrikeModule')
    @patch('sys.stdin')
    def test_run_error(self, mock_stdin, MockCrowdStrikeModule):
        import json

        input_data = {
            "config": {
                "clientId": "dummy_clientId",
                "clientSecret": "dummy_clientSecret",
                "targetHostName": "hostname2",
                "outputFile": "C:\\\\tmp\\\\file.txt"
            },
            "data": "testuser"
        }

        mock_stdin.isatty.return_value = False
        mock_stdin.read.return_value = json.dumps(input_data)

        analyzer = crowdstrikeAnalyzer()

        analyzer.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.clientId': 'dummy_clientId',
            'config.clientSecret': 'dummy_clientSecret',
            'config.targetHostName': 'hostname2',
            'config.outputFile': 'C:\\\\tmp\\\\file.txt',
            'data': 'testuser'
        }[x])

        mock_instance = MockCrowdStrikeModule.return_value
        mock_instance.runCloudScript.side_effect = Exception("API failure")

        analyzer.unexpectedError = MagicMock()
        analyzer.data_type = "username"
        analyzer.run()

        analyzer.unexpectedError.assert_called_once()


if __name__ == '__main__':
    unittest.main()
