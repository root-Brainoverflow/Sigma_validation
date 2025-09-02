# Sigma Rule Validator v1.0

Sigma Rule Validator is a tool that automatically parses and validates
[Sigma rules](https://sigmahq.io/) written in YAML format.\
It uses **LibYAML** to parse YAML files into C structures (`Rule`) and
validates the key Sigma fields:\
`id`, `status`, `date`, `logsource`, `detection`, `level`, and `tags`.

------------------------------------------------------------------------

## Features

-   **YAML Parsing**\
    Uses `libyaml` to parse `.yaml` files into structured C objects.

-   **Human-readable Output**\
    Displays parsed Sigma rules in a clear and readable format.

-   **Validation Checks**

    -   YAML syntax validation using **yamllint**\
    -   `id`: UUID format validation\
    -   `status`: must be one of `stable`, `test`, `experimental`,
        `deprecated`, `unsupported`\
    -   `date`: must follow `YYYY-MM-DD` format\
    -   `logsource`: valid category check\
    -   `detection`: validate selections, fields, and conditions\
    -   `level`: must be one of `informational`, `low`, `medium`,
        `high`, `critical`

------------------------------------------------------------------------

## Environment

-   macOS (development and testing)\
-   C Language (C11 recommended)\
-   Dependencies: **LibYAML**, **yamllint**

------------------------------------------------------------------------

## Installation

### 1) Install Homebrew (skip if already installed)

``` bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2) Install LibYAML

``` bash
brew install libyaml
```

### 3) Install yamllint

``` bash
brew install yamllint
# or
pip install yamllint
```

------------------------------------------------------------------------

## Build

### Basic build

``` bash
gcc -o sigma_validator Sigma_rule_validation_program.c -lyaml
```

### With explicit Homebrew paths (Apple Silicon example)

``` bash
/usr/bin/cc Sigma_rule_validation_program.c \
  -g -I/opt/homebrew/include \
  -L/opt/homebrew/lib -lyaml \
  -o Sigma_rule_validation_program
```

Or using `pkg-config`:

``` bash
cc Sigma_rule_validation_program.c $(pkg-config --cflags --libs yaml-0.1) -o Sigma_rule_validation_program
```

------------------------------------------------------------------------

## Run

``` bash
./sigma_validator
```

Enter the Sigma rule file path when prompted:

    Enter Sigma file path (.yaml) > rules/a.yaml

------------------------------------------------------------------------

## Example Output

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

------------------------------------------------------------------------

## Notes & Limitations

-   Only `.yaml` files are supported.\
-   If **yamllint** fails, validation stops immediately.\
-   The `Rule` struct has fixed buffer sizes: rules with **too many
    selections or details** may be truncated.

------------------------------------------------------------------------

## Troubleshooting

-   **`yaml.h` not found**\
    → Run `brew --prefix libyaml` to find the install path and add it
    with `-I` and `-L`.

-   **Linker error: `-lyaml` not found**\
    → Add `-L/opt/homebrew/lib` (Apple Silicon) or `-L/usr/local/lib`
    (Intel).

-   **yamllint not recognized**\
    → Install via `pipx install yamllint` or
    `pip install --user yamllint` to fix PATH issues.

------------------------------------------------------------------------

## VS Code Setup (optional)

To simplify build and debug in VS Code:

### `.vscode/tasks.json`

``` json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "build (libyaml)",
      "type": "shell",
      "command": "/usr/bin/cc",
      "args": [
        "Sigma_rule_validation_program.c",
        "-g",
        "-I/opt/homebrew/include",
        "-o",
        "Sigma_rule_validation_program",
        "/opt/homebrew/opt/libyaml/lib/libyaml.dylib"
      ],
      "problemMatcher": ["$gcc"],
      "group": { "kind": "build", "isDefault": true }
    }
  ]
}
```

### `.vscode/launch.json`

``` json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "(lldb) Run",
      "type": "cppdbg",
      "request": "launch",
      "program": "${workspaceFolder}/Sigma_rule_validation_program",
      "cwd": "${workspaceFolder}",
      "MIMode": "lldb",
      "preLaunchTask": "build (libyaml)",
      "externalConsole": true,
      "args": []
    }
  ]
}
```

> Adjust `/opt/homebrew` if you are on Intel (`/usr/local` is typical).

------------------------------------------------------------------------

## License

This project is licensed under the MIT License.
