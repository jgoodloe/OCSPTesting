# OCSP Server Test Suite

A comprehensive testing application for OCSP (Online Certificate Status Protocol) servers with both GUI and monitoring capabilities. This tool runs structured tests against OCSP servers and provides detailed reporting with exportable results (JSON/CSV).

## Screenshots

![OCSP Testing GUI - Main Interface](assets/Screenshot%202025-10-22%20125739.png)

![OCSP Testing GUI - Monitoring Tab](assets/Screenshot%202025-10-22%20125817.png)

## Features

- **Comprehensive OCSP Testing**: Protocol compliance, security, performance, and status validation
- **CRL Monitoring**: Certificate Revocation List checking and validation
- **GUI Interface**: User-friendly Windows application with real-time monitoring
- **Export Capabilities**: Results exportable in JSON and CSV formats
- **Certificate Validation**: Supports PEM/DER certificate formats
- **Advanced Testing**: IKEv2 in-band OCSP, signed client requests, and more

## System Requirements

### External Software Dependencies

#### 1. Git
**Required Version**: Git 2.0+ (for cloning the repository)
**Purpose**: Version control and repository cloning

**Installation Instructions:**

**Windows:**
```bash
# Option 1: Download installer (recommended)
# Download from: https://git-scm.com/download/win
# Run the installer and follow the setup wizard

# Option 2: Using Chocolatey
choco install git

# Option 3: Using Scoop
scoop install git
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install git
```

**Linux (CentOS/RHEL/Fedora):**
```bash
# CentOS/RHEL
sudo yum install git

# Fedora
sudo dnf install git
```

**macOS:**
```bash
# Using Homebrew
brew install git

# Or download from: https://git-scm.com/download/mac
```

**Verification:**
```bash
git --version
# Should show Git 2.0.0 or higher
```

#### 2. Python and pip
**Required Version**: Python 3.10+ (tested with Python 3.13)
**Purpose**: Runtime environment and package management

**Installation Instructions:**

**Windows:**
```bash
# Download from: https://www.python.org/downloads/
# Ensure "Add Python to PATH" is checked during installation
# pip comes included with Python installation

# Verify pip installation
python -m pip --version
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3.10 python3.10-pip python3.10-venv

# Alternative: Install latest Python
sudo apt install python3 python3-pip python3-venv
```

**Linux (CentOS/RHEL/Fedora):**
```bash
# CentOS/RHEL
sudo yum install python3.10 python3.10-pip

# Fedora
sudo dnf install python3 python3-pip

# If pip is not available, install it manually
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
```

**macOS:**
```bash
# Using Homebrew
brew install python@3.10
# pip comes included with Python

# Or download from: https://www.python.org/downloads/
```

**Verification:**
```bash
python --version
# Should show Python 3.10.0 or higher

pip --version
# Should show pip version information
```

#### 3. OpenSSL
**Required Version**: OpenSSL 1.1.1+ or OpenSSL 3.0+
**Purpose**: Used extensively for certificate operations, OCSP requests, and CRL processing

**Installation Instructions**:

**Windows:**
```bash
# Option 1: Using Chocolatey (recommended)
choco install openssl

# Option 2: Using Scoop
scoop install openssl

# Option 3: Manual installation
# Download from: https://slproweb.com/products/Win32OpenSSL.html
# Install to a directory in your PATH (e.g., C:\OpenSSL-Win64\bin)
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install openssl
```

**Linux (CentOS/RHEL/Fedora):**
```bash
# CentOS/RHEL
sudo yum install openssl

# Fedora
sudo dnf install openssl
```

**macOS:**
```bash
# Using Homebrew
brew install openssl

# Using MacPorts
sudo port install openssl
```

**Verification:**
```bash
openssl version
# Should show OpenSSL 1.1.1+ or 3.0+
```


### GUI Requirements

#### Windows
- **tkinter**: Included with Python standard library
- **No additional setup required**

#### Linux
- **tkinter**: May need separate installation
```bash
# Ubuntu/Debian
sudo apt install python3-tk

# CentOS/RHEL/Fedora
sudo yum install tkinter
```

#### macOS
- **tkinter**: Included with Python standard library
- **No additional setup required**

## Installation

### Prerequisites
Before installing the OCSP Testing Tool, ensure you have installed:
1. **Git** (for cloning the repository)
2. **Python 3.10+** with pip (for running the application)
3. **OpenSSL** (for certificate operations)

See the [System Requirements](#system-requirements) section above for detailed installation instructions.

### 1. Clone or Download
```bash
git clone <repository-url>
cd OCSPTesting
```

### 2. Create Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 4. Verify Installation
```bash
# Check Git installation
git --version

# Check Python and pip installation
python --version
pip --version

# Check Python dependencies
python -c "import cryptography, requests, asn1crypto; print('All dependencies installed successfully')"

# Check OpenSSL availability
openssl version
```

## Usage

### GUI Application
```bash
python app.py
```

### Command Line Testing (Future Feature)
```bash
# Planned for future releases
python -m ocsp_tester.cli --ocsp-url <URL> --issuer <cert-file>
```

## Input Requirements

### Required Inputs
- **OCSP URL**: The endpoint to test (e.g., `http://host/ocsp`)
- **Issuer CA Certificate**: PEM or DER format certificate file

### Optional Inputs
- **Known Good Certificate**: For positive test cases
- **Known Revoked Certificate**: For negative test cases  
- **Unknown CA Certificate**: For cross-CA testing
- **Client Signing Certificate/Key**: For signed request tests

## Test Categories

### Protocol Tests
- Basic OCSP request/response validation
- Certificate ID matching
- Response format compliance

### Security Tests
- Signature verification
- Nonce handling
- Request signing validation

### Performance Tests
- Latency measurement
- Load testing capabilities
- Concurrent request handling

### Status Tests
- Good certificate validation
- Revoked certificate detection
- Unknown certificate handling

### CRL Tests
- CRL download and parsing
- Certificate revocation checking
- CRL signature validation

## Export Formats

### JSON Export
- Complete test results with timestamps
- Detailed error information
- Test configuration details

### CSV Export
- Tabular format for spreadsheet analysis
- Summary statistics
- Easy filtering and sorting

## Troubleshooting

### Common Issues

#### Git Not Found
```bash
# Windows: Download and install from https://git-scm.com/download/win
# Or using Chocolatey: choco install git

# Linux (Ubuntu/Debian): sudo apt install git
# Linux (CentOS/RHEL): sudo yum install git
# macOS: brew install git
```

#### Python or pip Not Found
```bash
# Windows: Download from https://www.python.org/downloads/
# Ensure "Add Python to PATH" is checked during installation

# Linux (Ubuntu/Debian): sudo apt install python3 python3-pip
# Linux (CentOS/RHEL): sudo yum install python3 python3-pip
# macOS: brew install python@3.10

# Verify pip installation
python -m pip --version
```

#### OpenSSL Not Found
```bash
# Windows: Add OpenSSL to PATH
set PATH=%PATH%;C:\OpenSSL-Win64\bin

# Linux/macOS: Install OpenSSL
sudo apt install openssl  # Ubuntu/Debian
brew install openssl      # macOS
```

#### tkinter Import Error (Linux)
```bash
sudo apt install python3-tk  # Ubuntu/Debian
sudo yum install tkinter     # CentOS/RHEL
```

#### Permission Denied (Windows)
- Run Command Prompt as Administrator
- Ensure OpenSSL is in system PATH

### Verification Commands
```bash
# Check Git installation
git --version

# Check Python and pip installation
python --version
pip --version

# Check all Python dependencies
python -c "
import sys
print(f'Python: {sys.version}')
try:
    import cryptography
    print(f'cryptography: {cryptography.__version__}')
except ImportError as e:
    print(f'cryptography: {e}')
try:
    import requests
    print(f'requests: {requests.__version__}')
except ImportError as e:
    print(f'requests: {e}')
try:
    import asn1crypto
    print(f'asn1crypto: {asn1crypto.__version__}')
except ImportError as e:
    print(f'asn1crypto: {e}')
"

# Check OpenSSL installation
openssl version
```

## Advanced Configuration

### Environment Variables
- `TEMP`: Directory for temporary files (Windows)
- `TMPDIR`: Directory for temporary files (Linux/macOS)

### Network Configuration
- Ensure firewall allows HTTP/HTTPS connections to OCSP servers
- Proxy settings may need to be configured for corporate networks

## Support

For issues and questions:
1. Check this README for common solutions
2. Verify all dependencies are properly installed
3. Check system logs for detailed error messages
4. Ensure OpenSSL and Python are in your system PATH

## License

MIT License

Copyright (c) 2025 OCSP Testing Tool

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.