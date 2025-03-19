# Rapid7 Vulnerability Management - Create Asset Group

## Overview
This responder creates a new asset group on your **Rapid7 Vulnerability Management** instance and adds assets obtained from the **Rapid7VMGetAssetList** analyzer.

## Configuration
To use this responder, configure the following parameters:

- **userName** (string, required): Username for your Rapid7 VM instance.
- **password** (string, required): Password for your Rapid7 VM instance.
- **instanceURL** (string, required): URL for your Rapid7 VM instance.
- **verifyCertificate** (boolean, optional, default: false): Set to `false` if your Rapid7 VM instance uses a self-signed certificate.
- **thehiveInstance** (string, required): URL for your TheHive instance.
- **thehiveApiKey** (string, required): API Key for your TheHive instance.

## Usage
This responder is designed for **TheHive** & **Cortex**, integrating into SOAR workflows.

### Process Flow

1. **TheHive** receives a new case or artifact related to a `cve`.
2. The **Rapid7VMGetAssetList** analyzer retrieves affected assets.
3. The **Rapid7VMCreateAssetGroup** responder creates an asset group in Rapid7 VM.
4. Assets from the analyzer's results are added to the new asset group.

### Expected Results

- A new dynamic asset gorup is created in Rapid7 VM.
- The affected assets retrieved from the analyzed are added to this group.
