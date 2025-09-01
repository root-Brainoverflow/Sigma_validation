# Sigma Rule Validator v1.0

Sigma Rule Validator is a tool that automatically parses and validates [Sigma rules](https://sigmahq.io/) written in YAML format.  
It is built on **LibYAML** to parse YAML files into C structures (`Rule`) and validates the main Sigma fields (`id`, `status`, `date`, `logsource`, `detection`, `level`, `tags`).  

---

## Features

- **YAML Parsing**  
  Uses `libyaml` to parse Sigma rule `.yaml` files into a structured `Rule` object  

- **Readable Output**  
  Displays parsed Sigma rules in a human-friendly format  

- **Validation Checks**  
  - Basic YAML syntax validation using `yamllint`  
  - UUID format validation  
  - `status` value validation (`stable`, `test`, `experimental`, `deprecated`, `unsupported`)  
  - `date` format validation (`YYYY-MM-DD`)  
  - `logsource` category validation  
  - Validation of `detection` selections, fields, and conditions  
  - `level` value validation (`informational`, `low`, `medium`, `high`, `critical`)  

---

## Environment

- macOS (development and testing environment)  
- C Language (C11 recommended)  
- Dependencies: **LibYAML**, **YAMLLint**  

---

## Installation

### 1. Install Homebrew (skip if already installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Install LibYAML
```bash
brew install libyaml
```

### 3. Install yamllint (Python-based)
```bash
brew install yamllint
```
or
```bash
pip install yamllint
```

---

## Build

```bash
gcc -o sigma_validator main.c -lyaml
```

---

## Run

```bash
./sigma_validator
```

Enter the Sigma rule file path when prompted, for example:

```text
Enter Sigma file path (.yaml) > rules/test_rule.yaml
```

---

## Example Output

```
+--------------------------------------------------------------------------+
|                       SIGMA Rule Validator v1.0                          |
+--------------------------------------------------------------------------+

Enter Sigma file path (.yaml) > a.yaml


+--------------------------- YAMLlint VALIDATION --------------------------+

----------------------------------- RESULT ---------------------------------

sample_rule.yaml
  1:1       warning  missing document start "---"  (document-start)

+--------------------------------------------------------------------------+


+---------------------------  PARSED SIGMA RULE ---------------------------+
title: Suspicious Encoded PowerShell Command
id: 35c1fe1a-9d10-4e9b-a71d-ec9c8c9d1234
status: experimental
description: >
  Detects PowerShell executions that leverage the -EncodedCommand
  switch, a common technique used by attackers to hide malicious payloads
  in base64-encoded strings.
author: Brainoverflow
date: 2025-08-08
modified: 2025-08-25
references:
  - https://attack.mitre.org/techniques/T1059/001/

logsource:
  product: windows
  category: process_creation

detection:
  sel_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  sel_cmd:
    CommandLine|contains|all:
      - '-enc'
      - 'encodedcommand'

  condition: sel_img and sel_cmd

level: high
tags:
  - attack.execution
  - attack.t1059.001
+--------------------------------------------------------------------------+


+--------------------------- SIGMA RULE VALIDATION ------------------------+

[PASS] VALID SIGMA ID
[PASS] VALID SIGMA STATUS
[PASS] VALID SIGMA DATE
[PASS] VALID SIGMA LOGSOURCE
[PASS] VALID SIGMA DETECTION - VALID FIELD
[PASS] VALID SIGMA DETECTION - VALID CONDITION
[PASS] VALID SIGMA LEVEL

+---------------------------- VALIDATION COMPLETE -------------------------+
```

---

## Notes

- Only `.yaml` files are supported  
- If `yamllint` fails, the program will stop  
- The `Rule` struct has fixed sizes, so rules with **too many selections/details** may be truncated  

---

## License

This project is licensed under the MIT License.
