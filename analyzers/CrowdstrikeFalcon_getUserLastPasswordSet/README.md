# CrowdStrike Falcon - Get User Last Password Set 🛡️

## Overview
This analyzer retrieves the last password update date for a given username using **CrowdStrike FalconComplete**.

## Configuration
- **clientSecret** (string, required): Your FalconComplete API client secret.
- **clientId** (string, required): Your FalconComplete API client ID.
- **targetHostName** (string, required): Your AD host name.
- **outputFile** (string, required, default: `C:\temp\PasswordSet.txt`): Path to store the temporary results.

## Usage
This analyzer is designed for **TheHive** & **Cortex**, integrating into SOAR workflows.

### Script Setup:
To use this analyzer, you first need to upload the required PowerShell script to your CrowdStrike instance. You can get the script from the following location:

- **Script**: [PasswordLastSetRetriever.ps1](https://github.com/JohnRequejoLopez/PowershellUsefulScripts/blob/main/PasswordLastSet/PasswordLastSetRetriever.ps1)

Once you have the script, follow these steps:

1. **Download the PowerShell script**: Click on the link above to access the script in GitHub, and then download it to your local machine.
2. **Upload to CrowdStrike**: Log in to your CrowdStrike Falcon console, navigate to the **Real-Time Response** (RTR) section, and go to the **Scripts** tab.
3. **Add the Script**: Upload the downloaded script (`PasswordLastSetRetriever.ps1`) to the **Scripts** section of your CrowdStrike instance.

Once uploaded, the script will be available to execute in real-time response sessions, allowing you to retrieve the last password update date for a given user.
