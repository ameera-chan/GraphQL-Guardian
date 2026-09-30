# GraphQL Guardian

GraphQL Guardian is a security testing tool for GraphQL APIs. It provides a command line interface and a web dashboard.

Use the tool only on systems that you own or have permission to test.

## Install on Ubuntu with the Debian package

The included package was built and tested on Ubuntu 24.04. Open a terminal in this folder and run:

```bash
sudo apt update
sudo apt install ./dist/guardql_1.0.0_all.deb
guardql doctor
```

Run a scan with:

```bash
guardql scan -u "<target-website>" --profile default
```

## Requirements

- Python 3.10 or later
- Node.js and npm for the web dashboard

## Install from source

Download or copy this folder, open PowerShell in the folder, and run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Install the optional ML support with:

```powershell
python -m pip install -e ".[ml]"
```

## Run a scan

```powershell
guardql scan -u "<target-website>" --profile default
```

View all commands with:

```powershell
guardql --help
```

## Run the web dashboard

```powershell
guardql web
```

The first dashboard run installs the frontend packages.
