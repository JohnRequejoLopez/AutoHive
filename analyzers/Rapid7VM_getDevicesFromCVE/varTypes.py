from typing import (
    TypedDict, 
    List, 
    Dict, 
    Optional, 
    Union
)

##################### VULNERABILITY MANAGEMENT #####################

class AssetInfo(TypedDict, total=False):
    id: Optional[str]
    hostname: str
    ipAddress: str
    users: List[str]

class AssetGroupResponse(TypedDict, total=False):
    description: str
    name: str
    searchCriteria: Dict[str, Union[str, List[Dict[str, str]]]]
    type: str

class VulnerabilityInfo(TypedDict, total=False):
    id: Optional[str]
    since: Optional[str]
    status: Optional[str]
    results: List[Dict[str, Union[str, int, bool]]]

class APIResponse(TypedDict, total=False):
    error: Optional[str]
    page: Optional[Dict[str, int]]
    resources: Optional[List[Dict[str, Union[str, int, bool, List[Dict[str, str]]]]]]

class CVEAssetsResponse(TypedDict, total=False):
    cve: str
    affected_assets: List[AssetInfo]

class AssetGroupQueryResponse(TypedDict, total=False):
    asset_groups: List[AssetGroupResponse]

class AllAssetsResponse(TypedDict, total=False):
    assets: List[AssetInfo]

class AssetVulnerabilitiesResponse(TypedDict, total=False):
    assetId: str
    vulnerabilities: List[VulnerabilityInfo]
