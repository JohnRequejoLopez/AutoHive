import unittest
from unittest.mock import patch, MagicMock, mock_open
from analyzers.CrowdstrikeFalcon_getUserLastPasswordSet.falconComplete_getUserLastPasswordSet import crowdstrikeAnalyzer


class testCrowdstrikeAnalyzer(unittest.TestCase):
    
    @patch('analyzers.CrowdstrikeFalcon_getUserLastPasswordSet.crwd.CrowdStrikeModule')
    @patch('sys.stdin', new_callable=mock_open)
    def test_run_successful(self, MockCrowdStrikeModule, mock_stdin):
        """
        Test case to simulate a successful run of the 'crowdstrikeAnalyzer'.
        This test mocks the 'CrowdStrikeModule' and verifies that the 'report' function is called
        with the expected result when the analyzer completes successfully.
        """
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
        mock_stdin.write(json.dumps(input_data))
        mock_stdin.seek(0)
        # Create an instance of the analyzer
        analyzer = crowdstrikeAnalyzer()

        # Simulate the input parameters using MagicMock to mock the get_param method
        analyzer.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.clientId': 'dummy_clientId',       # Simulating the clientId parameter
            'config.clientSecret': 'dummy_clientSecret', # Simulating the clientSecret parameter
            'config.targetHostName': 'hostname1',   # Simulating the target hostname
            'config.outputFile': 'C:\\\\tmp\\\\file.txt',  # Simulating the output file path
            'data': 'testuser'  # Simulating the username that will be analyzed
        }[x])

        # Create a mock instance of the 'CrowdStrikeModule' to simulate interactions with the API
        mock_instance = MockCrowdStrikeModule.return_value

        # Mock the methods of the CrowdStrikeModule to simulate a successful API call
        mock_instance.runCloudScript.return_value = None  # Simulating a successful cloud script run
        mock_instance.getFileContent.return_value = ('{"password_last_set": "2025-04-09"}', '')  # Simulating JSON content
        mock_instance.deleteTmpFile.return_value = None  # Simulating file deletion
        mock_instance.close_rtr_session.return_value = None  # Simulating session close

        # Mock the 'report' function to verify it gets called with the expected data
        analyzer.report = MagicMock()

        # Set the 'data_type' to 'username' and run the analyzer
        analyzer.data_type = "username"
        analyzer.run()

        # Verify that the 'report' method was called once with the expected parameters
        analyzer.report.assert_called_once_with({
            'summary': {
                'username': 'testuser',
                'LastPasswordSet': 'password_last_set_date'
            }
        })

    @patch('analyzers.CrowdstrikeFalcon_getUserLastPasswordSet.crwd.CrowdStrikeModule')
    @patch('sys.stdin', new_callable=mock_open)
    def test_run_error(self, MockCrowdStrikeModule, mock_stdin):
        """
        Test case to simulate an error during the execution of the 'crowdstrikeAnalyzer'.
        This test mocks the 'CrowdStrikeModule' and ensures that the 'unexpectedError' function is called
        when an exception is raised during the run.
        """
        # Create an instance of the analyzer
        analyzer = crowdstrikeAnalyzer()

        # Simulate the input parameters using MagicMock to mock the get_param method
        analyzer.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.clientId': 'dummy_clientId',       # Simulating the clientId parameter
            'config.clientSecret': 'dummy_clientSecret', # Simulating the clientSecret parameter
            'config.targetHostName': 'hostname2',   # Simulating the target hostname
            'config.outputFile': 'C:\\\\tmp\\\\file.txt',  # Simulating the output file path
            'data': 'testuser'  # Simulating the username to be analyzed
        }[x])

        # Create a mock instance of the 'CrowdStrikeModule' to simulate interactions with the API
        mock_instance = MockCrowdStrikeModule.return_value

        # Simulate an exception being raised during the 'runCloudScript' call
        mock_instance.runCloudScript.side_effect = Exception("API failure")

        # Mock the 'unexpectedError' function to verify it gets called in case of an exception
        analyzer.unexpectedError = MagicMock()

        # Set the 'data_type' to 'username' and run the analyzer
        analyzer.data_type = "username"
        analyzer.run()

        # Verify that the 'unexpectedError' method was called once to handle the exception
        analyzer.unexpectedError.assert_called_once()

if __name__ == '__main__':
    unittest.main()
