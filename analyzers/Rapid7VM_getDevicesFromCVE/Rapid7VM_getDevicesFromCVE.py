#!/bin/python3
from cortexutils.analyzer import Analyzer

class rapid7VMAnalyzer(Analyzer):
    """
    Reference: 
    """
    def __init__(self):
        Analyzer.__init__(self)

        self.userName = self.get_param('config.userName', None, 'Missing your Rapid7 VM\'s username.')
        self.password = self.get_param('config.password', None, 'Missing your Rapid7 VM\'s password.')
        self.url = self.get_param('config.instanceURL', None, 'Missing your Rapid7 VM instance\'s url.') 

        self.__r7Conn = None

    def run(self):
        from .Rapid7 import vulnerabilityManagement

        try:
            if self.data_type == "cve":
                
                self.__r7Conn = vulnerabilityManagement(url=self.url, username=self.userName, password=self.password)
                
                self.report(
                    {
                        'summary': self.__r7Conn.getAssetListByCVE(cve=self.get_param('data'))
                    }
                )

            else:
                self.notSupported()

        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        level = "high"
        namespace = "Rapid7VM"
        predicate = "CVEInfo"
        values = []

        ids = []
        
        raw = raw['summary']
        
        # Extracting CVE info and affected assets
        cve = raw.get('cve', 'Unknown CVE')
        values.append(f"CVE: {cve}")

        taxonomies.append(
            self.build_taxonomy(
                'info', namespace, 'AffectedHosts', len(raw.get('affected_assets'))
            )
        )
        
        return {"taxonomies": taxonomies}
    
    def artifacts(self, raw):
        artifacts = []
        raw = raw.get('summary')
        for asset in raw.get('affected_assets', []):
            artifacts.append(self.build_artifact("host_name",asset["hostname"],tags=["hostname=" + asset["hostname"], "external_ip"]))

        return artifacts

if __name__ == '__main__':
    rapid7VMAnalyzer().run()
