from typing import (
    TypedDict, 
    List, 
    Union,
    Any, 
    Literal, 
    Optional,
    Dict
)

########################### THE HIVE ############################

##################### GENERAL #####################

apiKey = Union[str, int]

##################### OBSERVABLES #####################

observableId = str

class inputObservable(TypedDict, total=False):
    data: str
    dataType: str
    message: str
    ioc: bool
    isZip: bool
    zipPassword: bool
    attachment: str

class initializationnputUpdateObservable(TypedDict, total=False):
    dataType: str
    message: str
    tags: List[str]
    ioc: bool

##################### ALERTS #####################

alertId = Union[str, int]

alertStateValue = Literal[
    "phishing",
    "malware",
    "webDefacement"
]

alertSource = Literal[
    "secbutler",
    "crowdstrike",
    "proofpoint",
    "threatAdvisor"
]

class inputAlert(TypedDict, total=False):
    """"""
    type: alertStateValue
    source: alertSource
    sourceRef: str
    title: str
    severity: str
    observables: List[inputObservable]

##################### TASKS #####################

class inputTask(TypedDict, total=False):
    """"""
    title: str
    group: str
    description: str
    status: str
    flag: bool
    startDate: int
    endDate: int
    order: int
    dueDate: int
    assignee: str
    mandatory: bool

##################### CASES #####################
caseId = Union[str, int]

caseStateValue = Literal[
    "New",
    "InProgress",
    "Indeterminate",
    "FalsePositive",
    "TruePositive",
    "Duplicated",
    "Other",
]

class caseState:
    """"""
    new: caseStateValue = "New"
    inprogress: caseStateValue = "InProgress"
    indeterminate: caseStateValue = "Indeterminate"
    falsepositive: caseStateValue = "FalsePositive"
    truepositive: caseStateValue = "TruePositive"
    duplicated: caseStateValue = "Duplicated"
    other: caseStateValue = "Other"

class inputCreateCase(TypedDict,total=False):
    """"""
    severity: int
    startDate: int
    endDate: int
    tags: List[str]
    flag: bool
    tlp: int
    pap: int
    status: caseStateValue
    summary: str
    assignee: str
    caseTemplate: str
    tasks: List[inputTask]

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
