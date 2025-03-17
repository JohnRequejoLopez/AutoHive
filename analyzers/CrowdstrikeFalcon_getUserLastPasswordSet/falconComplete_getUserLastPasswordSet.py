#!/bin/python3
from cortexutils.analyzer import Analyzer

class crowdstrikeAnalyzer(Analyzer):
    """
    Reference: 
    """
    def __init__(self):
        Analyzer.__init__(self)

        self.clientId = self.get_param('config.clientId', None, 'Missing your CRWD\'s clientId.')
        self.clientSecret = self.get_param('config.clientSecret', None, 'Missing your CRWD\'s clientSecret.')
        self.targetHostName = self.get_param('config.targetHostName', None, 'Missing your AD hostname.') 
        self.outputFile = self.get_param('config.outputFile', None, 'Missing your outputFile.').encode().decode('unicode_escape')

        self.__crwdConn = None

    def run(self):
        from crwd import CrowdStrikeModule

        try:
            if self.data_type == "username":
                
                self.__crwdConn = CrowdStrikeModule(clientId=self.clientId, clientSecret=self.clientSecret, targetHostname=self.targetHostName)
                self.__crwdConn.runCloudScript(username=self.get_param('data'), outputFilePath=self.outputFile, cloudFileName="Get-PasswordLastSet.ps1")
                stdout_output, stderr_output = self.__crwdConn.getFileContent(filePath=self.outputFile)
                
                if stdout_output:
                    result= stdout_output
                else:
                    result = "No content received from the file."
            
                if stderr_output:
                    result= f"Command Error (stderr): {stderr_output}"
            
                self.__crwdConn.deleteTmpFile(filePath=self.outputFile)
                self.__crwdConn.close_rtr_session()
                
                self.report(
                    {
                        'summary': {
                            "username": self.get_param('data'),
                            "LastPasswordSet": result
                        } 
                    }
                )

            else:
                self.notSupported()

        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        raw = raw['summary']

        taxonomies.append(
            self.build_taxonomy(
                'info', CRWD, 'LastPasswordChangeDate', raw['LastPasswordSet']
            )
        )
        
        return {"taxonomies": taxonomies}
    
    
    def artifacts(self, raw):
        artifacts = []
        raw = raw.get('summary')
        artifacts.append(
            self.build_artifact(
                "user_name",raw["username"],tags=["username=" + raw["LastPasswordSet"], "LastPasswordSet"]
                )
            )

        return artifacts
if __name__ == '__main__':
    crowdstrikeAnalyzer().run()