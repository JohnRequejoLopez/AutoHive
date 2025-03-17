from typing import (
    TypedDict, 
    List, 
    Union,
    Optional,
    Dict
)

##################### CROWDSTRIKE #####################
class FalconResponse(TypedDict, total=False):
    body: Dict[str, List[Dict[str, Union[str, bool, int]]]]
    errors: List[Dict[str, str]]
    meta: Dict[str, Union[Dict[str, int], str]]  = tuple[str, dict]

class DeviceInfo(TypedDict, total=False):
    device_id: str
    hostname: str
    os_type: str
    status: str
    last_seen: Optional[str] 
    first_seen: Optional[str] 
    platform_name: Optional[str]  
    external_ip: Optional[str]  
    internal_ip: Optional[str]  
    fqdn: Optional[str] 