# Statistical Contingency Analysis Platform
## File Requirements and Compatibility Guidelines

### Overview
This document outlines the file requirements and limitations for the Statistical Contingency Analysis Platform. Understanding these requirements will ensure successful data import and analysis.

### Excel File Format Requirements

#### Supported File Formats
- **Primary Format**: Excel Workbook (.xlsx)
- **Secondary Format**: Excel 97-2003 Workbook (.xls) - limited support

#### File Size Limitations
- **Maximum File Size**: 100MB
- **Recommended Size**: Files under 50MB provide optimal performance
- **Sheet Limitations**: Maximum of 100 worksheets per file
- **Minimum Requirements**: Files must contain standard Excel file structure components

#### Technical Specifications
- Files must be valid Excel workbooks with standard internal structure
- Files must not contain embedded macros, executables, or scripts
- Symbolic links and network paths are not supported
- Files with corrupted internal structure will be rejected

### Data Structure Requirements

#### Required Format for Contingency Tables
- **First Column**: Contains identifiers (numbers or text)
- **Subsequent Columns**: Each column represents a category with its name as the header
- **Cell Values**: Numeric counts (integer values) representing frequency data
- **Structure**: No empty rows or columns within the data area

#### Example Contingency Table Format
```
Unit_ID     | Category_A | Category_B | Category_C | Category_D
------------|------------|------------|------------|------------
Unit_001    |     45     |     12     |     3      |     0
Neuron_002  |     8      |     67     |     15     |     2
Neuron_003  |     2      |     5      |     89     |     1
```

#### Data Type Requirements
- **Headers**: Text (string) values
- **Identifiers**: Alphanumeric text or numeric values 
- **Counts**: Integer numeric values
- **Missing Values**: Use zero (0) rather than blank cells or text indicators like "N/A"

### Best Practices for File Preparation

#### Data Preparation Recommendations
1. **Clean Your Data**:
   - Remove any extraneous rows, columns, or formatting
   - Ensure all values in count cells are numeric
   - Validate that all required categories are included

2. **Optimize File Size**:
   - Remove unused worksheets
   - Clear formatting from cells outside your data area
   - Consider splitting very large datasets into multiple files

3. **Formatting Guidelines**:
   - Avoid merged cells, conditional formatting, and data validation rules
   - Keep column headers simple and concise
   - Use consistent naming conventions for identifiers

#### Validation Before Import
- Verify row and column counts meet minimum requirements (at least 2 categories and 2 rows)
- Ensure all cells in the data area contain valid values
- Check that column headers are unique and descriptive

### Troubleshooting Common Issues

#### Import Failures
- **"Invalid Excel File Structure"**: The file may have been created or modified with incompatible software. Try saving as a new Excel file from Microsoft Excel.
- **"File Too Large"**: Reduce file size by removing unnecessary data, sheets, or formatting.
- **"Insufficient Data"**: Ensure your data meets the minimum requirements (multiple categories, multiple rows).
- **"Invalid File Type"**: Confirm you're using .xlsx or .xls format. Convert other formats to Excel before importing.

#### Data Analysis Errors
- **"No Contingency Tables Found"**: Verify your data follows the required structure with appropriate headers and numeric values.
- **"Insufficient Observations"**: Statistical analysis requires adequate sample sizes across categories.
- **"Invalid Category Data"**: Ensure all category cells contain numeric values only.

### Creating Compatible Files

#### Recommended Tools
- **Microsoft Excel**: Provides best compatibility (2016 or newer recommended)
- **LibreOffice Calc**: Generally compatible, but save in .xlsx format
- **Google Sheets**: Export as .xlsx for best results

#### Template Usage
- Use the provided templates whenever possible
- Do not modify the structure of template files
- Ensure data is pasted into the correct locations

### Contact and Support
For additional assistance with file formatting or import issues:
- Email: support@traceseis.com
- Help Documentation: Available through the Help menu in the application
- User Forum: [support.traceseis.com/forum](https://support.traceseis.com/forum)

---

© 2025 TraceSeis, Inc. All rights reserved.
Statistical Contingency Analysis Platform v1.0
