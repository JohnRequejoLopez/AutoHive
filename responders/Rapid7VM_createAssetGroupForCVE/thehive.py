from varTypes import (
    apiKey,
    caseId,
    initializationnputUpdateObservable,
    observableId
)

class TheHive:
    def __init__(self, url: str, api_key: apiKey) -> None:
        """
        Initializes an instance of the TheHive class.
        
        Args:
            url (str): The base URL of the TheHive instance.
            api_key (apiKey): The API key used to authenticate the connection to TheHive.
        """
        self.thehive_url = url
        self.api_key = api_key
        self.hive = self.__initializeInstance__()
        self.__checkUserPermissions__()

    def __initializeInstance__(self) -> None:
        """
        Initializes and returns a TheHiveApi client instance using the provided API key.
        
        This method is automatically called during class initialization to establish 
        the connection to TheHive using the `thehive4py` client.

        Returns:
            TheHiveApi: An authenticated instance of the TheHiveApi client.
        """
        from thehive4py import TheHiveApi
        
        return TheHiveApi(
            url=self.thehive_url,
            apikey=self.api_key
        )

    def __checkUserPermissions__(self) -> None:
        """
        nitializes and returns a TheHiveApi client instance using the provided API key.
        
        This method is automatically called during class initialization to establish 
        the connection to TheHive using the `thehive4py` client.

        Returns:
            It raises an error if given API KEY doesn't fill with the needed permissions
        """
        userObject = self.hive.user.get_current()
        
        if userObject['profile'].lower() == 'analyst':
            pass
        else:
            return {'error': f"API key of {userObject['name']} is missing an analyst profile. Users current `profile`: {userObject['profile']}"} 
                 
    def getCaseObservable(self, case_id: caseId) -> dict:
        """
        Retrieves the observables of a case by its ID.
        
        This method retrieves the observables associated with a case in TheHive using the provided case ID.

        Args:
            case_id (caseId): The ID of the case from which observables are to be retrieved.

        Returns:
            dict: A dictionary containing the observables associated with the case or an error message in case of failure.
        """
        try:
            return self.hive.case.find_observables(case_id=case_id)
        except Exception as e:
            return {'error': f"Failed to retrieve observables for case: {str(e)}"}

    def updateObservable(self, observableId: observableId, fields: initializationnputUpdateObservable) -> dict:
        """
        Updates an observable in TheHive with the given fields.
    
        This method allows updating an existing observable identified by its ID with 
        new data provided in the `fields` argument.

        Args:
            observableId (observableId): The ID of the observable to update.
            fields (initializationnputUpdateObservable): A dictionary containing the fields to update.

        Returns:
            dict: A dictionary containing the updated observable details or an error message in case of failure.
        """
        try: 
            return self.hive.observable.update(observable_id=observableId, fields=fields)
        except Exception as e:
            return {'error': f"Failed to update observabl with {observableId} id: {e}"}