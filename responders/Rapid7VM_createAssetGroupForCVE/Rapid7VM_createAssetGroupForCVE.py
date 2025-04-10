#!/bin/python3
from cortexutils.responder import Responder

class rapid7VMResponder(Responder):
    """
    Reference: 
    """
    def __init__(self):
        Responder.__init__(self)
        
        self.userName = self.get_param('config.userName', None, 'Missing your Rapid7 VM\'s username.')
        self.password = self.get_param('config.password', None, 'Missing your Rapid7 VM\'s password.')
        self.url = self.get_param('config.instanceURL', None, 'Missing your Rapid7 VM instance\'s url.')
        self.__thehiveInstance = self.get_param('config.thehiveInstance', None, 'Missing your TheHive\'s url.')
        self.__thehiveApiKey = self.get_param('config.thehiveApiKey', None, 'Missing your TheHive\'s Api-Key.')

        self.__thehiveConn = None
        self.__r7Conn = None

    def __now__(self):
        from datetime import datetime

        return f"{datetime.utcnow().strftime('%Y/%m/%d - %H:%M')} UTC"
    
    def validateInput(self, input_data):
        if 'dataType' not in input_data.get('data', {}):
            self.error("Missing 'dataType' field in input data.")

    def run(self):

        from .thehive import TheHive
        from .Rapid7 import vulnerabilityManagement

        try:
            self.__thehiveConn = TheHive(url=self.__thehiveInstance, api_key=self.__thehiveApiKey)
            self.__r7Conn = vulnerabilityManagement(url=self.url, username=self.userName, password=self.password)

            self.validateInput(self._input)

            data = self.get_param('data', {})

            cve = None
            observableId = None

            if data.get('dataType') and data.get('dataType').lower() == 'cve':
                cve = groupName = data['data']
                observableId = data['_id']
            else:
                caseObservables = self.__thehiveConn.getCaseObservable(case_id=data.get('_id', ''))

                for observable in caseObservables:
                    if observable.get('dataType') == 'cve':
                        cve = groupName = observable.get('data')
                        observableId = observable.get('_id')
                        break

            if cve is None:
                return self.error("No CVE observable type was found on this case.")

            response = self.__r7Conn.createAssetGroup(groupName=groupName, cve=cve)

            groupId = response.get('id')

            if not groupId:  
                groupInformation = self.__r7Conn.getAssetGroupByName(groupName=groupName).get('resources', [])

                for groupInf in groupInformation:
                    if groupInf.get('id'):
                        groupId = groupInf['id']
                        break  

            if not groupId:
                return self.error("Failed to retrieve group ID from Rapid7VM. Try it again later.")

            fields = {
                "tags": [f"Rapid7VM:{cve}:GroupId:{groupId}"],
                "message": f"Asset group created at Rapid7VM on {self.__now__()}. {self.url}/group.jsp?groupid={groupId}.\nServiceNow ticket raised with ID: <here goes your snow ticket id>."
            }

            self.__thehiveConn.updateObservable(observableId=observableId, fields=fields)

            return self.report({"url": f"{self.url}/group.jsp?groupid={groupId}"})

        except Exception as e:
            self.error(f"Error performing operation: {e}")

if __name__ == '__main__':
    rapid7VMResponder().run()