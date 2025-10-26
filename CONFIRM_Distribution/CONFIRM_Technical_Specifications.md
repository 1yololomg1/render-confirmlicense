# CONFIRM Statistical Validation Engine
## Technical Specifications

**Copyright (c) 2024 TraceSeis, Inc. All rights reserved.**

This software and associated documentation files (the "Software") are proprietary and confidential to TraceSeis, Inc. and its affiliates. The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties.

**Contact Information:**
- Email: info@traceseis.com or alvarochf@traceseis.com
- Created by: Alvaro Chaveste (deltaV solutions)

Unauthorized copying, distribution, or modification of this Software is strictly prohibited and may result in severe civil and criminal penalties.

---

### **Software Information**
- **Application Name**: CONFIRM Statistical Validation Engine
- **Version**: 1.0.0
- **Developer**: TraceSeis, Inc.® - deltaV solutions division
- **License Type**: Commercial Software License
- **Platform**: Windows 64-bit

### **System Requirements**

#### **Minimum Requirements**
- **Operating System**: Windows 10 (64-bit) or later
- **Processor**: Intel Core i3 or AMD equivalent
- **Memory**: 8 GB RAM
- **Storage**: 100 MB available space
- **Network**: Internet connection for license validation
- **Display**: 1280x720 resolution minimum

#### **Recommended Requirements**
- **Operating System**: Windows 11 (64-bit)
- **Processor**: Intel Core i5 or AMD equivalent
- **Memory**: 16 GB RAM
- **Storage**: 500 MB available space (SSD recommended)
- **Network**: Stable broadband connection
- **Display**: 1920x1080 resolution or higher

### **Supported File Formats**

#### **Input Formats**
- **Microsoft Excel**: .xlsx, .xls
- **Excel 97-2003**: .xls
- **Excel 2007+**: .xlsx

#### **Output Formats**
- **Excel Reports**: .xlsx
- **Chart Images**: .png, .jpg
- **Project Files**: .json (internal format)

### **Statistical Methods Implemented**

#### **Contingency Analysis**
- **Chi-Square Test**: Independence testing
- **Expected Frequencies**: Theoretical frequency calculations
- **Residual Analysis**: Standardized residuals
- **Significance Testing**: P-value calculations

#### **Correlation Analysis**
- **Pearson Correlation**: Linear relationship measurement
- **Significance Testing**: Statistical significance of correlations
- **Correlation Matrix**: Multi-variable correlation analysis

#### **Data Validation**
- **Type Checking**: Data type validation
- **Range Validation**: Value range checking
- **Missing Value Detection**: Null/empty value identification
- **Outlier Detection**: Statistical outlier identification

### **Security Features**

#### **License Protection**
- **Hardware Fingerprinting**: CPU ID, motherboard serial, MAC address
- **Encrypted Storage**: Fernet encryption for license data
- **Online Validation**: Server-side license verification
- **Anti-Tampering**: Runtime protection against modification

#### **Data Security**
- **File Validation**: Security scanning before processing
- **Local Processing**: No data transmission to external servers
- **Encrypted Storage**: Secure configuration and license storage
- **Memory Protection**: Secure memory cleanup on exit

### **Performance Specifications**

#### **Processing Capabilities**
- **File Size**: Up to 500 MB Excel files
- **Sheet Count**: Up to 50 worksheets per file
- **Data Rows**: Up to 1 million rows per sheet
- **Concurrent Processing**: Multi-threaded analysis

#### **Memory Usage**
- **Base Memory**: ~200 MB
- **Processing Memory**: 2-4 GB for large files
- **Peak Memory**: Up to 8 GB for maximum file sizes

#### **Processing Speed**
- **Small Files** (< 1 MB): < 30 seconds
- **Medium Files** (1-10 MB): 1-5 minutes
- **Large Files** (10-100 MB): 5-30 minutes
- **Very Large Files** (> 100 MB): 30+ minutes

### **Dependencies**

#### **Python Libraries**
- **pandas**: Data manipulation and analysis
- **numpy**: Numerical computing
- **scipy**: Scientific computing and statistics
- **matplotlib**: Plotting and visualization
- **seaborn**: Statistical data visualization
- **scikit-learn**: Machine learning algorithms
- **openpyxl**: Excel file handling
- **requests**: HTTP library for license validation
- **cryptography**: Encryption and security

#### **System Libraries**
- **tkinter**: GUI framework
- **threading**: Multi-threading support
- **json**: Data serialization
- **hashlib**: Cryptographic hashing
- **base64**: Data encoding
- **platform**: System information
- **uuid**: Unique identifier generation

### **Architecture**

#### **Application Structure**
- **Main Application**: StatisticalAnalyzer class
- **License Management**: LicenseDialog and validation system
- **Data Processing**: Multi-threaded batch processing
- **Visualization**: Chart generation and display
- **Export System**: Results and chart export

#### **Threading Model**
- **Main Thread**: GUI and user interaction
- **Processing Threads**: Statistical analysis (up to 4 workers)
- **Background Threads**: License validation and monitoring
- **Thread Safety**: Comprehensive locking and synchronization

### **Configuration**

#### **User Settings**
- **Default Export Format**: Excel (.xlsx)
- **Default Export Directory**: Documents/CONFIRM_Results
- **Processing Timeout**: 30 minutes
- **Maximum Workers**: 4 concurrent threads
- **Auto-Save**: Project auto-save enabled

#### **System Configuration**
- **Log Level**: INFO
- **Log File**: ~/.confirm/confirm.log
- **Config Directory**: ~/.confirm/
- **License File**: ~/.confirm/confirm_license.json
- **Settings File**: ~/.confirm/settings.json

### **Error Handling**

#### **Validation Errors**
- **File Security**: Malicious file detection
- **Data Format**: Invalid data structure handling
- **License Issues**: License validation error handling
- **Network Errors**: Connection failure handling

#### **Processing Errors**
- **Memory Errors**: Insufficient memory handling
- **Timeout Errors**: Processing timeout handling
- **Data Errors**: Invalid data handling
- **Thread Errors**: Threading exception handling

### **Logging**

#### **Log Levels**
- **DEBUG**: Detailed debugging information
- **INFO**: General application information
- **WARNING**: Warning messages
- **ERROR**: Error conditions
- **CRITICAL**: Critical error conditions

#### **Log Output**
- **File Logging**: ~/.confirm/confirm.log
- **Console Logging**: Standard output
- **Format**: Timestamp - Logger - Level - Message

### **Build Information**

#### **Build Tools**
- **PyInstaller**: Executable creation
- **UPX**: Executable compression
- **Custom Obfuscation**: Code protection
- **Commercial Protection**: Anti-debugging and anti-tampering

#### **Executable Properties**
- **File Size**: ~81 MB
- **Compression**: UPX compressed
- **Protection**: Commercial-grade obfuscation
- **Dependencies**: All included (standalone)

### **License Server**

#### **Server Information**
- **Primary Server**: https://render-confirmlicense.onrender.com
- **Backup Server**: https://confirm-license-manager-default-rtdb.firebaseio.com
- **Protocol**: HTTPS REST API
- **Authentication**: Token-based authentication

#### **License Tiers**
- **Professional Monthly**: Monthly subscription license
- **Professional Yearly**: Annual professional license
- **Enterprise**: Enterprise license with manual approval
- **Enterprise Yearly**: Annual enterprise license
- **Trial Version**: Limited trial license

### **Support Information**

#### **Contact Details**
- **Email**: info@traceseis.com or alvarochf@traceseis.com
- **Company**: TraceSeis, Inc.® - deltaV solutions division
- **Support Hours**: Business hours (EST)

#### **Documentation**
- **User Manual**: CONFIRM_User_Manual.md
- **Quick Start**: CONFIRM_Quick_Start_Guide.md
- **Technical Specs**: This document

---

*These technical specifications are based on the actual implementation of CONFIRM Statistical Validation Engine v1.0. For technical support, contact info@traceseis.com.*
