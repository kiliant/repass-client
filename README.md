# repass-client
## Install
RePass client is written in [Python](https://www.python.org/).
Dependencies are managed using [Poetry](https://python-poetry.org/).
[Install Poetry](https://python-poetry.org/docs/#installation) and run:
```
poetry install
poetry shell
```

Then you are in a shell with all necessary [Python](https://www.python.org/) versions and dependencies installed.

Alternatively, you can install the requirements listed in requirements.txt by using your favourite tool.

## Usage
Run RePass client with `python repass.py` within a Poetry shell.
RePass displays a menu regarding what can be done.
This can also be accessed by entering h.

### 1 generate
This creates a new credential on a FIDO2 token or a corresponding software solution and stores metadata, e.g., the credential handle and public key in a local file.

### a \[URL\] authenticate
This expects a valid URL pointing towards a RePass recovery request and that the appropriate credential is currently available, i.e., if applicable, the token is plugged in.

A challenge will be retrieved and authenticated automatically.

### l list
This lists all credentials, whose metadata is available locally.

### q quit
Exits the RePass client.
