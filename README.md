# CONFIRM Statistical Validation Engine

Professional statistical analysis software for validating machine learning models and clustering outputs (e.g., Self-Organizing Maps). CONFIRM processes Excel files containing classification data and provides comprehensive statistical validation including confusion matrices, correlation analysis, and performance metrics.

## What is CONFIRM?

CONFIRM is a Windows desktop application that:
- Validates classification/clustering model outputs from Excel spreadsheets
- Performs batch analysis on multiple sheets simultaneously
- Generates statistical reports, visualizations, and quality control metrics
- Supports machine learning model validation workflows

## Quick Start for Judges

### 1. System Requirements
- **Operating System**: Windows 10/11 (64-bit)
- **Memory**: 8 GB RAM minimum, 16 GB recommended
- **Storage**: 100 MB free space
- **Network**: Internet connection required for initial license activation only

### 2. Running the Software
1. **Extract the executable** from the submission package
2. **Double-click `CONFIRM.exe`** to launch
3. **Activate license** (see License Activation below)
4. **Load Excel file** - Click "Browse File" and select your data file
5. **Run analysis** - Click "Start Analysis" or "Batch Process All Sheets"

### 3. License Activation
1. When prompted, enter one of the license keys from `JUDGE_LICENSE_KEYS.txt`
2. Copy and paste the **entire license key** (includes colons)
3. Click "Activate" - the software will bind to your machine automatically
4. **Note**: Each license key works on ONE machine. If a key is already in use, try the next one.

**Sample License Keys** (see `JUDGE_LICENSE_KEYS.txt` for all 10 keys):
- `f0ab2a970a5da8ce:2026-04-11T11:59:51.774Z:345a2a93bcbf1e69`
- `6fe15926bc022b27:2026-04-11T12:00:20.254Z:da7129f9b475626b`

### 4. Sample Data
- **Sample Excel File**: `Loan_AI_CONFIRM_DEMO_IMPERFECT.xlsx` is included in the repository
- Use this file to test the software functionality
- The file demonstrates the expected Excel format

## Features

- **Batch Analysis**: Process multiple Excel sheets simultaneously for comprehensive statistical validation
- **Excel File Processing**: Supports standard Excel (.xlsx) format with multi-sheet processing
- **Statistical Validation**: Comprehensive analysis including confusion matrices, correlation analysis, and performance metrics

## Excel File Format

CONFIRM processes Excel files with the following expected format:

**Required Format:**
- **Row 1**: Column headers (first column should be "Neuron", "Unit", "SOM_Unit", "Cell", or "Node", followed by category headers)
- **Column A** (starting Row 2): Sequential integers (1, 2, 3, ...)
- **Columns B onward**: Numeric values (counts or proportions)
- **Multiple Sheets**: Supported for batch processing

**Example:**
```
Row 1: Neuron    Shale    Wet Sand    Tight Sand    Gas Sand
Row 2: 1         45       12          3             0
Row 3: 2         73       27          5             0
Row 4: 3         52       38          8             0
```

**Sample Excel File**: See `Loan_AI_CONFIRM_DEMO_IMPERFECT.xlsx` for a sample format.

## Batch Analysis

CONFIRM supports batch processing of multiple sheets within a single Excel file:

- **Multi-Sheet Processing**: Analyze all sheets or select specific sheets
- **Comparison Analysis**: Generate comparative statistics across multiple sheets
- **Efficient Processing**: Threaded processing for improved performance
- **Results Export**: Export batch analysis results to Excel format

## License

Copyright (c) 2024 TraceSeis, Inc. All Rights Reserved.

See [LICENSE](LICENSE) for full terms.

## License Keys for Contest Judges

For contest evaluation, see [JUDGE_LICENSE_KEYS.txt](JUDGE_LICENSE_KEYS.txt) for demo license keys.

## Third-Party Licenses

See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for attribution of third-party libraries and dependencies.

## Security

For security-related information, see [SECURITY_PUBLIC_REPO_CHECKLIST.md](SECURITY_PUBLIC_REPO_CHECKLIST.md).

## Contact

For licensing inquiries:
- Email: info@traceseis.com or alvarochf@traceseis.com
- Company: TraceSeis, Inc.

