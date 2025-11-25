# CONFIRM Statistical Validation Engine v1.0
## User Manual & Documentation

**Copyright (c) 2024 TraceSeis, Inc. All rights reserved.**

This software and associated documentation files (the "Software") are proprietary and confidential to TraceSeis, Inc. and its affiliates. The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties.

**Contact Information:**
- Email: info@traceseis.com or alvarochf@traceseis.com
- Created by: Alvaro Chaveste (deltaV solutions)

Unauthorized copying, distribution, or modification of this Software is strictly prohibited and may result in severe civil and criminal penalties.

---

### **Overview**
CONFIRM Statistical Validation Engine is a professional statistical analysis platform designed for comprehensive data validation and contingency analysis. The software provides advanced statistical processing capabilities for validating machine learning clustering models such as Self-Organizing Maps (SOMs).

### **System Requirements**
- **Operating System**: Windows 10/11 (64-bit)
- **Memory**: 8 GB RAM minimum, 16 GB recommended
- **Storage**: 100 MB free space
- **Network**: Optional internet connection for one-time activation (if required by your deployment)
- **File Support**: Microsoft Excel (.xlsx, .xls) files

### **Installation**

#### **Option 1: Automated Installation**
1. Run `install.bat` as Administrator
2. Follow the on-screen prompts
3. Desktop shortcut will be created automatically

#### **Option 2: Portable Installation**
1. Copy `CONFIRM.exe` to desired location
2. Double-click to run directly
3. No installation required

### **Activation & Setup (Operations-Managed)**

#### **First-Time Setup**
1. Launch CONFIRM.exe
2. If an activation prompt appears, follow the on-screen instructions once and continue to the dashboard
3. Activation is bound to your workstation automatically and maintained by TraceSeis operations

#### **Support**
- **Company**: TraceSeis, Inc.® - deltaV solutions division
- **Contact**: info@traceseis.com or alvarochf@traceseis.com
- **Security**: Activation data is stored locally and secured automatically

### **Main Features**

#### **1. Data Import & Management**
- **Supported Formats**: Excel (.xlsx, .xls) files
- **Multi-Sheet Support**: Process multiple worksheets simultaneously
- **Data Validation**: Automatic data structure validation
- **Security Validation**: File security scanning before processing
- **Preview System**: Sheet preview before processing

#### **2. Statistical Analysis Capabilities**
- **Contingency Analysis**: Advanced statistical contingency testing
- **Chi-Square Testing**: Statistical significance testing
- **Correlation Analysis**: Pearson correlation calculations
- **Distribution Analysis**: Statistical distribution evaluation
- **Data Quality Control**: Comprehensive QC analysis

#### **3. Batch Processing**
- **Multi-Sheet Processing**: Process multiple sheets in batch
- **Parallel Processing**: Multi-threaded analysis for performance
- **Progress Monitoring**: Real-time progress tracking
- **Error Handling**: Comprehensive error management

#### **4. Visualization & Charts**
- **Radar Charts**: Multi-dimensional data visualization
- **Pie Charts**: Proportional data representation
- **Distribution Charts**: Statistical distribution visualization
- **Summary Charts**: Statistical summary visualizations
- **Multi-Sheet Visualizations**: Comparative analysis charts

#### **5. Export & Reporting**
- **Excel Export**: Results exported to Excel format
- **Chart Export**: Individual chart export capability
- **Comparison Reports**: Multi-sheet comparison summaries
- **QC Reports**: Quality control analysis reports
- **Project Management**: Save and load analysis projects

### **User Interface**

#### **Main Window Components**
- **File Section**: File loading and validation
- **Analysis Section**: Statistical analysis controls
- **Results Section**: Analysis results display
- **Visualization Section**: Chart and graph controls
- **Export Section**: Results export options

#### **Menu System**
- **File Menu**: Project management, file operations
- **Analysis Menu**: Statistical analysis options
- **View Menu**: Display and visualization options
- **Help Menu**: Documentation and support

### **Workflow Guide**

#### **Step 1: Load Data**
1. Click "Browse File" to select Excel file
2. System validates file security and structure
3. Select sheets to process from preview
4. Click "Load Selected Sheets"

##### Understanding the Expected Excel Layout
Users most often run into trouble at this step because their contingency tables are formatted like standard spreadsheets with headers at the top or text identifiers in the first column. CONFIRM expects a compact matrix layout that looks more like numerical output than a traditional report.

```
Row 1: [empty]  [empty]     [empty]      [empty]
Row 2: 1        45          12           3
Row 3: 2        73          27           5
Row 4: 3        52          38           8
Row 5: 4        31          42           12
Row 6: Category Type_A      Type_B       Type_C
```

- **Row 1** should be blank (or contain null/NaN values). It acts as a spacer for the bottom headers.
- **Column A** must contain sequential integers (1, 2, 3, ...). Text such as "Supplier A" or "Category_1" will cause the file to be rejected.
- **Columns B onward** must contain purely numeric values (counts or proportions). Mixed text/numeric data triggers validation errors.
- **Last row** can include optional category labels. CONFIRM reads them after the data block is processed.
- **Headers sit at the bottom**, not the top, so the matrix can be parsed consistently.

###### Examples of formats that will be rejected

```
Row 1: Category   Type_A   Type_B   Type_C
Row 2: Supplier_A 45       12       3
Row 3: Supplier_B 73       27       5
```
(Text in the first column prevents the sheet from loading.)

```
Row 1: ID        Type_A   Type_B   Type_C
Row 2: 1         45       12       3
```
(Headers at the top cause the parser to misalign the rows.)

```
Row 1: 1         45       12       "N/A"
Row 2: 2         73       27       "missing"
```
(Mixed text and numeric values stop the statistical routines.)

#### **Step 2: Configure Analysis**
1. Choose analysis type (single sheet or batch)
2. Select statistical parameters
3. Configure processing options
4. Review settings before processing

#### **Step 3: Run Analysis**
1. Click "Start Analysis" or "Batch Process"
2. Monitor progress in real-time
3. View results as they become available
4. Review any warnings or errors

#### **Step 4: Review Results**
1. Examine statistical results
2. Review generated visualizations
3. Check quality control reports
4. Validate analysis accuracy

#### **Step 5: Export Results**
1. Select export format (Excel, charts)
2. Choose export location
3. Export individual results or complete report
4. Save project for future reference

### **Statistical Methods**

#### **Contingency Analysis**
- Chi-square test of independence
- Expected frequency calculations
- Residual analysis
- Statistical significance testing

#### **Correlation Analysis**
- Pearson correlation coefficient
- Statistical significance testing
- Correlation matrix generation
- Relationship strength assessment

#### **Data Validation**
- Data type validation
- Missing value detection
- Outlier identification
- Data consistency checking

### **Quality Control Features**

#### **Data Quality Checks**
- Missing value analysis
- Data type consistency
- Range validation
- Pattern recognition

#### **Statistical Validation**
- Assumption testing
- Normality testing
- Homogeneity testing
- Independence testing

### **Troubleshooting**

#### **Common Issues**
- **Activation Prompts**: Contact support if an unexpected activation message appears
- **File Loading**: Ensure Excel file is not corrupted
- **Memory Issues**: Close other applications if processing large files
- **Network Issues**: Check internet connection if your deployment relies on activation or remote resources

#### **Error Messages**
- **"Activation required"**: Confirm network access or contact support
- **"File security validation failed"**: File may be corrupted or unsafe
- **"Data validation failed"**: Check data format and structure
- **"Processing timeout"**: Large files may require more time

### **Support & Contact**

#### **Technical Support**
- **Email**: info@traceseis.com or alvarochf@traceseis.com
- **Company**: TraceSeis, Inc.® - deltaV solutions division
- **Documentation**: This user manual

#### **Activation Oversight (Operations)**
- **Workstation Binding**: Activation associates the tool with a single workstation
- **Transfer Requests**: Contact support if a workstation change is required
- **Status Checks**: Activation state is viewable from the application dashboard

### **Security Features**

#### **Operational Safeguards**
- Hardware fingerprinting (operations-managed)
- Encrypted activation cache
- Optional online activation check
- Anti-tampering protection

#### **Data Security**
- Secure file validation
- Encrypted data storage
- No data transmission to external servers
- Local processing only

### **Performance Optimization**

#### **System Requirements**
- Use SSD storage for better performance
- Ensure adequate RAM for large datasets
- Close unnecessary applications during processing
- Use wired internet connection for license validation

#### **File Size Recommendations**
- **Small files** (< 10 MB): Standard processing
- **Medium files** (10-100 MB): May require more time
- **Large files** (> 100 MB): Consider splitting data

### **Version Information**
- **Version**: 1.0.0
- **Build**: Commercial Release
- **Platform**: Windows 64-bit
- **Deployment**: Commercial distribution with operations-managed activation

---

*This documentation is based on the actual functionality implemented in CONFIRM Statistical Validation Engine v1.0. For technical support or license inquiries, contact info@traceseis.com.*
