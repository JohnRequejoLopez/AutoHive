# Rapid7 Vulnerability Management - Get Device List 

## Overview
This analyzer retrieves a list of assets that are vulnerable to a specified CVE using **Rapid7 Vulnerability Management**.

## Configuration
To use this analyzer, you need to configure the following parameters:

- **userName** (string, required): Username for your Rapid7 VM instance.
- **password** (string, required): Password for your Rapid7 VM instance.
- **instanceURL** (string, required): URL for your Rapid7 VM instance.
- **verifyCertificate** (boolean, optional, default: false): Set to false if your Rapid7 VM instance uses a self-signed certificate.

## Usage
This analyzer is designed for **TheHive** & **Cortex**, integrating into SOAR workflows.

### Script Setup:
This analyzer is designed to be used in TheHive & Cortex, integrating into SOAR workflows.

### ⚠️ Important Note ⚠️

To execute this analyzer successfully, you must add a new IOC type called `cve` in TheHive Console. This ensures that the system recognizes and processes the CVE input correctly.

### Process Flow

1. `TheHive` detects a new `cve` IOC and automatically creates a case.
2. The analyzer runs and queries Rapid7 VM for affected assets.
3. A list of vulnerable devices is retrieved and attached to the case.

### Expected Results

- List of devices affected by the specified CVE.
- Relevant data about each asset, such as IP address, hostname, and associated users.