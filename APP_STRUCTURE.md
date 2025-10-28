# CONFIRM Application Structure & Scaffold

## Overview
CONFIRM is a professional machine learning model validation tool that specializes in transforming clustering analysis results into statistical validation metrics. The software converts Self-Organizing Map (SOM) outputs and other clustering results into confusion matrices, calculating comprehensive performance statistics including precision, recall, F1-scores, and Chi-square tests. Developed by TraceSeis, Inc. (deltaV solutions division).

**Version:** 1.0.0  
**License:** Commercial (TraceSeis, Inc.)  
**Contact:** info@traceseis.com / alvarochf@traceseis.com

---

## Architecture Overview

### System Components
```
┌─────────────────────────────────────────────────────────────┐
│                    CONFIRM Application                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │   Client (GUI)   │◄───────►│  License Server  │         │
│  │  Python/Tkinter  │         │  Node.js/Render  │         │
│  └──────────────────┘         └──────────────────┘         │
│           │                            │                   │
│           │                            │                   │
│           ▼                            ▼                   │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │ Protection Module│         │  Firebase DB     │         │
│  │  Anti-Tampering  │         │  License Storage │         │
│  └──────────────────┘         └──────────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Client Application (`01_SOURCE_CODE/`)

#### 1.1 Main Application (`CONFIRM_Integrated.py`)
**Purpose:** Machine learning model validation engine with professional GUI

**Key Classes:**
- `StatisticalAnalyzer` - Main application class for clustering validation
- `LicenseEncryptionManager` - Handles encrypted license storage  
- `LicenseValidator` - License validation and caching

**Key Features:**
- **Clustering Model Validation**: Converts SOM/clustering results to confusion matrices
- **Statistical Analysis**: Chi-square, Cramer's V, precision, recall, F1-score calculations
- **Excel Processing**: Multi-sheet batch processing of clustering results
- **Performance Metrics**: Classification accuracy and model effectiveness evaluation
- **Visualization Suite**: Heatmaps, radar charts, distribution plots
- **Quality Control**: QC grading system for model performance
- **Batch Processing**: Multi-threaded analysis of multiple datasets

**Main Methods:**
```python
# License Management
- validate_license_activation()
- check_license_expiry()
- get_license_info()

# Clustering Model Validation
- process_excel_file()
- convert_clustering_to_confusion_matrix()
- analyze_contingency()
- calculate_som_effectiveness()
- get_chi_square_qc_summary()
- calculate_performance_metrics()

# UI Management
- create_license_panel()
- create_statistics_panel()
- create_qc_panel()
- show_results()

# File Operations
- load_excel_file()
- export_results()
- batch_process_directory()
```

**UI Structure:**
```
StatisticalAnalyzer
├── License Panel (Top)
│   ├── License Info Display
│   ├── License Status Indicator
│   └── License Action Buttons
├── Statistics Panel (Main)
│   ├── File Selection
│   ├── Analysis Type Selection
│   ├── Batch Processing Controls
│   └── Results Display Area
├── QC Panel (Advanced)
│   ├── Comparison Analysis
│   ├── Ranking System
│   ├── Statistical Summary
│   └── Best Configuration Recommender
└── Results Window (Separate)
    ├── Charts & Visualizations
    ├── Statistical Tables
    └── Export Options
```

#### 1.2 License Manager GUI (`license_manager_gui.py`)
**Purpose:** Administrative interface for license management

**Class:** `LicenseManagerGUI`

**Key Features:**
- License creation
- License search and lookup
- License verification
- License revocation
- System statistics dashboard

**Tabs:**
1. **System Overview** - Authentication and system stats
2. **License Management** - Search and view licenses
3. **Verify License** - Manual license verification
4. **Create License** - Generate new licenses
5. **Revoke License** - Revoke existing licenses

**Admin Operations:**
```python
- load_system_stats()
- search_licenses()
- get_current_hardware()
- verify_license()
- create_license()
- revoke_license()
```

#### 1.3 Protection Module (`protection_module.py`)
**Purpose:** Commercial software protection mechanisms

**Class:** `CommercialProtection`

**Protection Features:**
- **Anti-Debugging:** Detects debuggers (OllyDbg, x64dbg, IDA, etc.)
- **Anti-Tampering:** File integrity verification
- **Runtime Monitoring:** Continuous security checks
- **VM Detection:** Identifies virtual environments
- **Sandbox Detection:** Detects analysis environments
- **API Hooking Detection:** Identifies DLL injection attempts

**Security Checks:**
```python
# Process Monitoring
- Debugger process detection
- Analysis tool detection
- Hook detection

# Environment Checks
- Virtual machine detection
- Sandbox detection
- Execution path validation

# Integrity Validation
- File integrity checks
- Memory patching detection
- Code modification detection
```

---

### 2. License Server (`02_SERVER/`)

#### 2.1 Server Application (`server.mjs`)
**Purpose:** License management server with Firebase integration

**Technology Stack:**
- Node.js (Express)
- Firebase Realtime Database
- Deployed on Render.com

**API Endpoints:**

**Public Endpoints:**
```javascript
POST /validate
  - Validates license key
  - Checks hardware binding
  - Returns license status

POST /migrate-license
  - Migrates old format licenses
  - Handles legacy key conversion

POST /validate-cached
  - Session-based validation
  - Reduces server load
```

**Admin Endpoints (Protected):**
```javascript
POST /admin/create-license
  - Creates new licenses
  - Sets expiration dates
  - Assigns product types

POST /admin/search-licenses
  - Search by email, key, or fingerprint
  - Returns matching licenses

POST /admin/update-license
  - Update license status
  - Extend expiration
  - Unbind hardware

POST /admin/revoke-license
  - Revoke licenses
  - Track revocation reason

POST /admin/migrate-all-licenses
  - Bulk migration utility
  - Updates all old licenses

GET /admin/license-stats
  - System statistics
  - License breakdowns
  - Recent activity log

GET /admin/recent-licenses
  - Recent license activity
  - Dashboard data
```

**License Data Structure:**
```javascript
{
  id: "unique_id",
  license_key: "format:id:expiry:hash",
  email: "customer@example.com",
  tier: "professional|enterprise|student|startup",
  status: "active|inactive|revoked|migrated",
  expires: "ISO8601",
  created_at: "ISO8601",
  computer_id: "hardware_fingerprint",
  activated: boolean,
  activatedAt: "ISO8601",
  notes: "admin_notes",
  migration_history: []
}
```

#### 2.2 Deployment Configuration
**Files:**
- `render.yaml` - Render.com deployment config
- `package.json` - Node.js dependencies
- `RENDER_ENVIRONMENT_VARIABLES.md` - Environment setup guide

**Environment Variables:**
```bash
PORT=10000
FIREBASE_DATABASE_URL=<url>
LICENSE_SECRET=<secret>
ADMIN_SECRET_KEY=<admin_key>
```

---

### 3. Documentation (`03_DOCUMENTATION/`)

**User Documentation:**
- `CONFIRM_Quick_Start_Guide.md` - Quick start for users
- `CONFIRM_User_Manual.md` - Complete user manual
- `CONFIRM_Technical_Specifications.md` - Technical details

**Distribution Documentation:**
- `COPYRIGHT_NOTICE.txt` - Copyright information
- `README.txt` - Installation instructions
- `install.bat` - Windows installer script

---

### 4. Build & Distribution

#### 4.1 Build Scripts
- `build_new_exe.bat` - Windows batch build script
- `build_new_exe.py` - Python build automation

#### 4.2 Distribution Folders
- `CONFIRM_Distribution/` - Standard distribution
- `CONFIRM_Distribution_Optimized/` - Optimized build

---

## Data Flow

### License Activation Flow
```
1. User enters license key
   ↓
2. Client generates hardware fingerprint
   ↓
3. Client calls /validate endpoint
   ↓
4. Server validates license
   ↓
5. Server checks hardware binding
   ↓
6. Server returns validation result
   ↓
7. Client caches encrypted license
```

### License Validation Flow (Runtime)
```
1. Application starts
   ↓
2. Load cached license
   ↓
3. Check offline grace period
   ↓
4. If expired or offline:
   - Connect to server
   - Validate license
   - Update cache
   ↓
5. Display license status
```

### Machine Learning Validation Flow
```
1. User selects Excel file with clustering results
   ↓
2. Application loads neuron/category assignment data
   ↓
3. Convert clustering assignments to confusion matrix
   ↓
4. Calculate validation metrics in thread pool
   ↓
5. Compute precision, recall, F1, Chi-square, Cramer's V
   ↓
6. Generate model performance QC grading
   ↓
7. Create validation visualizations (heatmaps, radar charts)
   ↓
8. Display SOM effectiveness and classification results
   ↓
9. Export validation reports and charts
```

---

## Security Architecture

### License Protection Layers
1. **Hardware Binding** - License tied to machine fingerprint
2. **Encrypted Storage** - License data encrypted on disk
3. **Signature Validation** - Cryptographic signature verification
4. **Server Validation** - Online verification required
5. **Offline Grace Period** - 72-hour offline allowance
6. **Commercial Protection** - Anti-tampering mechanisms

### Hardware Fingerprinting
```python
Components Used:
- CPU ID
- Motherboard Serial
- BIOS Serial
- MAC Address

Hash Algorithm: SHA-256
Result: 64-character hex string
```

### License Key Format
```
{license_id}:{expiry_date}:{signature}

Example:
abc123def456:2025-12-31T23:59:59Z:a1b2c3d4e5f6
```

---

## Key Functionality

### Machine Learning Model Validation Features
1. **Clustering-to-Classification Conversion**
   - Transform SOM neuron assignments to predictions
   - Generate confusion matrices from clustering results
   - Calculate classification metrics from unsupervised learning

2. **Statistical Validation**
   - Chi-square test for association significance
   - Cramer's V for association strength
   - P-value computation for hypothesis testing
   - Expected vs. observed frequency analysis

3. **Performance Metrics**
   - Precision, Recall, F1-score per category
   - Overall classification accuracy
   - Model effectiveness scoring
   - SOM utilization analysis

4. **Quality Control & Comparison**
   - QC grading (A-F) for model performance
   - Multi-model comparison and ranking
   - Best configuration recommendation
   - Cross-validation statistical summaries

### UI Components
1. **Main Window**
   - License status display
   - File selection controls
   - Analysis type selection
   - Results display area

2. **Results Window**
   - Statistical tables
   - Charts and graphs
   - QC indicators
   - Export options

3. **License Panel**
   - License information
   - Status indicator
   - Action buttons
   - Details popup

---

## Configuration & Settings

### User Configuration
**Location:** `~/.confirm/settings.json`

```json
{
  "terms_accepted": true,
  "terms_accepted_date": "2025-01-01T00:00:00",
  "license_info": {
    "license_key": "encrypted",
    "last_validated": "ISO8601",
    "days_remaining": 365,
    "tier": "professional"
  },
  "preferences": {
    "theme": "default",
    "auto_load_last_file": true
  }
}
```

### License Cache
**Location:** `~/.confirm/confirm_license.json` (encrypted)

---

## Threading & Performance

### Thread Pool Configuration
- **Max Workers:** 2 (configurable)
- **Pool Timeout:** 30 seconds
- **Cleanup Timeout:** 10 seconds

### Batch Processing
- Parallel sheet processing
- Progress tracking
- Cancellation support
- Error handling per sheet

### Performance Optimizations
- Lazy loading of heavy libraries
- Cached license validation
- Efficient memory management
- Matplotlib figure cleanup

---

## Error Handling

### Error Categories
1. **License Errors**
   - Invalid license
   - Expired license
   - Network timeout
   - Offline mode limits

2. **File Processing Errors**
   - File format errors
   - Missing sheets
   - Data validation failures
   - Memory errors

3. **System Errors**
   - Thread pool failures
   - UI crashes
   - Resource cleanup errors

### Logging System
- File logging to `~/.confirm/confirm.log`
- Console output for debugging
- Structured log format with timestamps
- Error traceback capture

---

## Dependencies

### Core Dependencies
```python
# GUI
tkinter >= 8.6
ttk

# Data Processing
pandas >= 1.5.0
numpy >= 1.23.0

# Visualization
matplotlib >= 3.6.0
seaborn >= 0.12.0

# Statistics
scipy >= 1.9.0

# Security
cryptography >= 3.4.0
requests >= 2.28.0

# System
psutil >= 5.9.0
```

### Server Dependencies
```json
{
  "express": "^4.18.0",
  "firebase-admin": "^11.0.0",
  "cors": "^2.8.5"
}
```

---

## Build Process

### Windows Executable Build
1. Install PyInstaller
2. Run `build_new_exe.bat`
3. Bundle with dependencies
4. Include documentation
5. Create installer package

### Distribution Package
```
CONFIRM_Distribution/
├── CONFIRM.exe
├── install.bat
├── README.txt
├── CONFIRM_Quick_Start_Guide.md
├── CONFIRM_Technical_Specifications.md
└── CONFIRM_User_Manual.md
```

---

## API Integration

### Server Communication
- **Base URL:** Configurable via environment variable
- **Timeout:** 15 seconds (configurable)
- **Retry Logic:** Automatic retry on network errors
- **Authentication:** Admin secret key in headers

### Request Flow
```python
1. Check offline grace period
2. Validate cached license
3. If expired, call server
4. Parse response
5. Update cache
6. Return status
```

---

## Testing & Validation

### Validation Points
1. License activation on first run
2. Terms acceptance prompt
3. Hardware fingerprinting verification
4. Server connectivity test
5. File format validation
6. Statistical calculations verification

---

## Future Enhancements

### Planned Features
- [ ] Multi-language support
- [ ] Cloud synchronization
- [ ] Advanced statistical methods
- [ ] Custom visualization options
- [ ] Batch scheduling
- [ ] API integration for external tools

---

## Support & Maintenance

### Support Channels
- Email: info@traceseis.com
- Technical Contact: alvarochf@traceseis.com

### Maintenance Tasks
- Regular license validation
- Server health monitoring
- Log rotation
- Performance optimization
- Security updates

---

## License Model

### License Tiers
1. **Student** - Annual license
2. **Startup** - Monthly license
3. **Professional** - Monthly/Yearly
4. **Enterprise** - Monthly/Yearly with support
5. **Integration** - Annual OEM license
6. **White-label** - Annual rebranding license

### License Restrictions
- Single machine activation
- Hardware-bound binding
- Time-based expiration
- Tier-based feature access

---

*Last Updated: 2025-01-02*
*Document Version: 1.0*
