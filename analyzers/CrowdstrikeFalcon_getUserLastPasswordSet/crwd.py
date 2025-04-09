from falconpy import (
    Hosts, 
    RealTimeResponse
)

from .varTypes import (
    FalconResponse,
    DeviceInfo
)

class CrowdStrikeModule:
    def __init__(self, clientId: str, clientSecret: str, targetHostname: str) -> None:
        """
        Initializes an instance of the CrowdStrikeModule class.
        Args:
            client_id (str): The CrowdStrike API client ID.
            client_secret (str): The CrowdStrike API client secret.
        """
        self.hosts = Hosts(client_id=clientId, client_secret=clientSecret)
        self.falcon = RealTimeResponse(client_id=clientId, client_secret=clientSecret)
        self.sessionId = None

        
        deviceId = self.__findDeviceByHostname__(targetHostname=targetHostname)
        self.sessionId = self.__startRTRSession__(device_id=deviceId)

    def __handleResponse__(self, response: FalconResponse, operationName: str) -> dict:
        """
        Handles the API response for common checks.
        Returns: Retrieves information obtained from the API
        """
        resources = response.get("body", {}).get("resources", [])
        
        if not resources:
            raise Exception(f"Failed to {operationName}. No resources found.")
        
        return resources

    def __findDeviceByHostname__(self, targetHostname: str) -> DeviceInfo:
        """
        Finds a device by its hostname.
        Returns: The device information.
        """
        response = self.hosts.query_devices_by_filter(filter=f"hostname:'{targetHostname}'")
        resources = self.__handleResponse__(response, "find device by hostname")
        
        return resources[0]

    def __startRTRSession__(self, device_id: str) -> str:
        """
        Starts a Real-Time Response session for a specific device.
        Returns: The session ID.
        """
        session_response = self.falcon.init_session(device_id=device_id)
        resources = self.__handleResponse__(session_response, "start RTR session")
        
        session_id = resources[0].get('session_id', None)
        
        if not session_id:
            raise Exception("Failed to start RTR session.")
        
        return session_id

    def __executeRTRCommand__(self, commandType: str, commandString: str) -> dict:
        """
        Executes a generic RTR command.
        Returns: It retrieves the information returned by falcon.
        """
        response = self.falcon.execute_active_responder_command(
            session_id=self.sessionId,
            base_command=commandType,
            command_string=commandString,
            timeout=60
        )
        
        errors = response.get('body', {}).get('errors', [])
        if errors:
            raise Exception(f"Error executing command. {errors[0]['message']}")
        
        return response.get('body', {}).get('resources', [])

    def runCloudScript(self, username: str, outputFilePath: str, cloudFileName: str = "PasswordLastSetRetriever.ps1") -> str:
        """
        Executes a runScript in the Real-Time Response session.
        Args:
            username: The username for the command.
            cloudFileName: The cloud file name. Defaults to https://github.com/JohnRequejoLopez/PowershellUsefulScripts/tree/main/PasswordLastSet.
        Returns: The cloud request ID.
        """
        commandString = f'runscript -CloudFile="{cloudFileName}" -CommandLine="-Username {username} -outputFile {outputFilePath}"'

        commandResponse = self.__executeRTRCommand__(commandType="runscript", commandString=commandString)
        
        return commandResponse[0].get('cloud_request_id')

    def checkCommandState(self, cloudRequestId: str) -> tuple:
        """
        Retrieves the output of a command from the RTR session.
        Returns: The command output (stdout, stderr).
        """
        import time

        for _ in range(5):
            output_response = self.falcon.check_command_status(cloud_request_id=cloudRequestId)
            resources = output_response.get("body", {}).get("resources", [])
            
            if resources and resources[0].get("complete"):
                return resources
                
            time.sleep(5)
        raise Exception("Failed to retrieve the output after multiple attempts.")

    def getCloudRequestId(self, fileContent: dict) -> str:
        """
        Extracts the cloud request ID from the file content response.
        Returns: The cloud request ID.
        """
        return fileContent[0].get('cloud_request_id')

    def getFileContent(self, filePath: str) -> tuple:
        """
        Retrieves the content of the temporary file created during the RTR session.
        Returns: The stdout and stderr of the file content.
        """
        commandString = f"cat {filePath}"

        file_content_response = self.__executeRTRCommand__(commandType="cat", commandString=commandString)
        
        cloud_request_id = self.getCloudRequestId(fileContent=file_content_response)
        file_content = self.checkCommandState(cloudRequestId=cloud_request_id)
        
        if file_content:
            stdout_output = file_content[0].get("stdout", "").strip()
            stderr_output = file_content[0].get("stderr", "").strip()
            return stdout_output, stderr_output

    def deleteTmpFile(self, filePath: str) -> None:
        """
        Deletes the temporary file created during the RTR session.
        """
        commandString = f"rm {filePath}"

        try:
            self.__executeRTRCommand__(commandType="rm", commandString=commandString)
        except Exception as e:
            raise Exception(f"Failed to delete temporary file: {str(e)}")

    def closeRtrSession(self) -> None:
        """
        Closes the RTR session.
        """
        self.falcon.batch_active_responder_command(session_id=self.sessionId, baseCommand="exit")