from varTypes import (
    APIResponse,
    CVEAssetsResponse,
    AssetGroupResponse,
    AssetVulnerabilitiesResponse,
    AllAssetsResponse
)
from typing import (
    List
)

class vulnerabilityManagement:
    def __init__(self, url: str, username: str, password: str) -> None:
        """
        Initializes an instance of the vulnerabilityManagement class.

        Args:
            url: The base URL of the Rapid7 instance.
            username: The username for API authentication.
            password: The password for API authentication.
        """
        from requests.auth import HTTPBasicAuth
        
        self.url = url
        self.auth = HTTPBasicAuth(username, password)
        self.__disableHTTPErrors__()

    def __disableHTTPErrors__(self) -> None:
        """
        Disables SSL/TLS warnings for insecure HTTPS requests.

        This method is used to suppress warnings related to unverified HTTPS requests
        when making API calls.
        """
        import urllib3
        
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def __makeRequest__(self, method: str, endpoint: str, params: dict = None, jsonData: dict = None) -> APIResponse:
        """
        A private method to make API requests.

        This method abstracts the HTTP request logic to avoid repetition across different functions.

        Args:
            method: The HTTP method (GET, POST, etc.).
            endpoint: The API endpoint (relative to the base URL).
            params: Query parameters for the request.
            jsonData: JSON payload for POST requests.

        Returns:
            dict: The JSON response from the API.
        """
        import requests
        
        url = f"{self.url}{endpoint}"
        
        try:
            response = requests.request(
                method=method,
                url=url,
                auth=self.auth,
                verify=False,
                params=params,
                json=jsonData
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def __processAssets__(self, response: APIResponse, affectedAssets: list) -> list:
            """
            Processes a response containing asset data and extracts relevant details.

            This function iterates through the list of assets returned in the API response,
            extracts key attributes such as asset ID, hostname, IP address, and associated users,
            and appends them to the affectedAssets list.

            Args:
                response: The API response containing asset details.
            Returns:
                affectedAssets: A list storing dictionaries of affected asset details.
            """ 
            for asset in response.get("resources", []):
                hostname = asset.get("hostName")
                
                if not hostname:
                    hostnames_list = asset.get("hostNames", [])
                
                    if hostnames_list and isinstance(hostnames_list, list) and hostnames_list[0]:
                        hostname = hostnames_list[0].get("name", "Unknown Hostname")
                    else:
                        hostname = "Unknown Hostname"

                affectedAssets.append({
                    "id": asset.get("id"),
                    "hostname": hostname,
                    "ipAddress": asset.get("ip") if asset.get("ip") else "Unknown IP Address",
                    "users": asset.get("users", []),
                })
            
            return affectedAssets

    def getAssetListByCVE(self, cve: str) -> CVEAssetsResponse:
        """
        Retrieves a list of assets affected by a specific CVE.

        This method queries the Rapid7 API to fetch assets that are vulnerable to a 
        given CVE identifier and returns a dictionary containing affected asset details.

        Args:
            cve: The CVE identifier used to filter assets.

        Returns:
            CVEAssetsResponse: A dictionary containing the CVE and a list of affected assets with details.
        """ 
        page = 0
        affectedAssets = []
        endpoint = "/api/3/assets/search"

        params = {"page": page}
        data = {
            "filters": [{"field": "cve", "operator": "is", "value": cve}],
            "match": "all",
        }

        response = self.__makeRequest__("POST", endpoint, params=params, jsonData=data)

        if not response or "page" not in response or "resources" not in response:
            return {"cve": cve, "affected_assets": affectedAssets}  # Return empty result

        total_pages = response.get("page", {}).get("totalPages", 0)

        affectedAssets = self.__processAssets__(response=response, affectedAssets=affectedAssets)

        while page < total_pages - 1:
            page += 1
            params["page"] = page
            response = self.__makeRequest__("POST", endpoint, params=params, jsonData=data)

            if not response or "resources" not in response:
                break  

            affectedAssets = self.__processAssets__(response=response, affectedAssets=affectedAssets)

        return {"cve": cve, "affected_assets": affectedAssets}
 
    def createAssetGroup(self, groupName: str, cve: list) -> AssetGroupResponse:
        """
        Creates a dynamic asset group based on a list of CVEs.

        This method sends a request to create an asset group that dynamically includes
        assets affected by the specified CVEs.

        Args:
            groupName: The name of the asset group to be created.
            cve: A list of CVE identifiers used as search criteria.

        Returns:
            AssetGroupResponse: The response from the API after attempting to create the asset group.
        """
        endpoint = "/api/3/asset_groups"

        data = {
            "description": "Assets with unacceptable high risk require immediate remediation.",
            "name": groupName,
            "searchCriteria": {
                "filters": [{"field": "cve", "operator": "is", "value": cve}],
                "match": "all"
            },
            "type": "dynamic"
        }

        return self.__makeRequest__("POST", endpoint, jsonData=data)

    def getAssetGroupByName(self, groupName: str) -> dict:
        """
        Retrieves details of an asset group by its name.

        This method queries the API to fetch an asset group that matches the provided name.

        Args:
            groupName: The name of the asset group to retrieve.

        Returns:
            dict: A dictionary containing the details of the asset group.
        """
        endpoint = "/api/3/asset_groups"
        params = {"name": groupName}

        return self.__makeRequest__("GET", endpoint, params=params)

    def getAssets(self) -> AllAssetsResponse:
        """
        Retrieves all assets from the Rapid7 API, handling pagination.
    
        This method makes multiple API calls if necessary to fetch all assets across multiple pages.
    
        Returns:
            AllAssetsResponse: A dictionary containing a list of all retrieved assets.
        """
        page = 0
        allAssets = []
        endpoint = "/api/3/assets"
        params = {"page": page}
    
        response = self.__makeRequest__("GET", endpoint, params=params)
    
        if not response or "page" not in response or "resources" not in response:
            return {"assets": allAssets}  
    
        total_pages = response.get("page", {}).get("totalPages", 0)

        allAssets = self.__processAssets__(response=response, affectedAssets=allAssets)
    
        while page < total_pages - 1:
            page += 1
            params["page"] = page
            response = self.__makeRequest__("GET", endpoint, params=params)
    
            if not response or "resources" not in response:
                break  
                
            allAssets = self.__processAssets__(response=response, affectedAssets=allAssets)
    
        return {"assets": allAssets}
    
    def __processVulnerabilities__(self, resources: dict, affectedVulnerabilities: list):
        """
        Processes the vulnerabilities from the given resources and extracts the relevant details.

        This function iterates through the list of vulnerability resources,
        extracts the vulnerability ID, the timestamp ('since'), status, and results,
        and appends them to the affectedVulnerabilities list.

        Args:
            resources: The API response containing vulnerability details.
            affectedVulnerabilities: The list to store the processed vulnerability details.

        Returns:
            affectedVulnerabilities: A list storing dictionaries of processed vulnerability details.
        """
        for resource in resources.get("resources", []):
            affectedVulnerabilities.append({
                "id": resource.get("id"),
                "since": resource.get("since"),
                "status": resource.get("status"),
                "results": resource.get("results", []),
            })

        return affectedVulnerabilities

    def getAssetsVulnerabilities(self, assetId: str) -> AssetVulnerabilitiesResponse:
        """
        Fetches the vulnerabilities associated with a given asset by making multiple API requests if necessary.
    
        This function retrieves the vulnerabilities of an asset identified by `assetId` from an external API.
        It handles pagination in the API response, processes the retrieved vulnerability data, 
        and returns a dictionary containing the asset ID along with a list of associated vulnerabilities.
    
        Args:
            assetId: The ID of the asset for which vulnerabilities are being fetched.
    
        Returns:
            AssetVulnerabilitiesResponse: A dictionary containing the asset ID and a list of vulnerabilities associated with that asset.
        """
        page = 0
        affectedVulnerabilities: List[VulnerabilityInfo] = []
        endpoint = f"/api/3/assets/{assetId}/vulnerabilities"

        params = {"page": page}
    
        response = self.__makeRequest__("GET", endpoint, params=params)
    
        if not response or "page" not in response or "resources" not in response:
            return {"assetId": assetId,"vulnerabilities": affectedVulnerabilities}  
    
        total_pages = response.get("page", {}).get("totalPages", 0)
    
        affectedVulnerabilities = self.__processVulnerabilities__(resources=response, affectedVulnerabilities=affectedVulnerabilities)
    
        while page < total_pages - 1:
            page += 1
            params["page"] = page
            response = self.__makeRequest__("GET", endpoint, params=params)
    
            if not response or "resources" not in response:
                break  
    
            affectedVulnerabilities = self.__processVulnerabilities__(resources=response, affectedVulnerabilities=affectedVulnerabilities)
        
        return {"assetId": assetId,"vulnerabilities": affectedVulnerabilities}  