import unittest
from unittest.mock import patch, MagicMock
from analyzers.Rapid7VM_getDevicesFromCVE.Rapid7VM_getDevicesFromCVE import rapid7VMAnalyzer


class TestRapid7Analyzer(unittest.TestCase):

    @patch('analyzers.Rapid7VM_getDevicesFromCVE.Rapid7.vulnerabilityManagement')
    @patch('sys.stdin')
    def test_run_successful(self, mock_stdin, MockVulnMgmt):
        import json

        input_data = {
            "config": {
                "userName": "dummy_userName",
                "password": "dummy_password",
                "instanceURL": "https://rapid7.local"
            },
            "data": "CVE-2025-TEST",
            "dataType": "cve"
        }

        
        mock_stdin.isatty.return_value = False
        mock_stdin.read.return_value = json.dumps(input_data)

        analyzer = rapid7VMAnalyzer()

        analyzer.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.userName': 'dummy_userName',
            'config.password': 'dummy_password',
            'config.instanceURL': 'https://rapid7.local',
            'data': 'CVE-2025-TEST'
        }[x])

        
        mock_instance = MockVulnMgmt.return_value
        mock_instance.getAssetListByCVE.return_value = {
            'cve': 'CVE-2025-TEST',
            'affected_assets': [
                {'id': '1', 'hostname': 'host1.local', 'ipAddress': '10.0.0.1', 'users': []},
                {'id': '2', 'hostname': 'host2.local', 'ipAddress': '10.0.0.2', 'users': []}
            ]
        }

        analyzer.report = MagicMock()
        analyzer.data_type = "cve"
        analyzer.run()

        analyzer.report.assert_called_once_with({
            'summary': {
                'cve': 'CVE-2025-TEST',
                'affected_assets': [
                    {'id': '1', 'hostname': 'host1.local', 'ipAddress': '10.0.0.1', 'users': []},
                    {'id': '2', 'hostname': 'host2.local', 'ipAddress': '10.0.0.2', 'users': []}
                ]
            }
        })

    @patch('analyzers.Rapid7VM_getDevicesFromCVE.Rapid7.vulnerabilityManagement')
    @patch('sys.stdin')
    def test_run_error(self, mock_stdin, MockVulnMgmt):
        import json

        input_data = {
            "config": {
                "userName": "dummy_userName",
                "password": "dummy_password",
                "instanceURL": "https://rapid7.local"
            },
            "data": "CVE-2025-TEST",
            "dataType": "cve"
        }

        mock_stdin.isatty.return_value = False
        mock_stdin.read.return_value = json.dumps(input_data)

        analyzer = rapid7VMAnalyzer()

        analyzer.get_param = MagicMock(side_effect=lambda x, *_: {
            'config.userName': 'dummy_userName',
            'config.password': 'dummy_password',
            'config.instanceURL': 'https://rapid7.local',
            'data': 'CVE-2025-TEST'
        }[x])

        # Simula una excepción lanzada por la librería Rapid7
        mock_instance = MockVulnMgmt.return_value
        mock_instance.getAssetListByCVE.side_effect = Exception("Simulated API error")

        analyzer.unexpectedError = MagicMock()
        analyzer.data_type = "cve"
        analyzer.run()

        analyzer.unexpectedError.assert_called_once()


if __name__ == '__main__':
    unittest.main()