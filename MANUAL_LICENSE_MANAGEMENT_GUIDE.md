# Manual License Creation and Revocation Guide

This guide explains how to use the new manual license creation and revocation features in your CONFIRM License Management System.

## 🎯 **What's New**

Your system now supports:
- ✅ **Manual License Creation** - Create licenses directly without Stripe payments
- ✅ **License Revocation** - Revoke existing licenses when needed
- ✅ **License Search** - Find licenses by email for easy management

## 🚀 **Quick Start**

### **1. Deploy Updated Server**
Make sure your `server.mjs` is deployed to Render.com with the new endpoints:
- `POST /admin/create-license` - Manual license creation
- `POST /admin/revoke-license` - License revocation
- `POST /admin/search-license` - Search licenses by email

### **2. Run the GUI**
```bash
python license_manager_gui.py
```

## 📋 **Manual License Creation**

### **When to Use Manual Creation**
- **Free trials** for potential customers
- **Demo licenses** for sales presentations
- **Replacement licenses** for technical issues
- **Special arrangements** with enterprise customers
- **Testing** during development

### **How to Create a License**

1. **Open the GUI** and go to the "Create License" tab
2. **Enter customer email** - This is where the license will be sent
3. **Select license type** from the dropdown:
   - `student` - Student license
   - `startup` - Startup license
   - `professional` - Professional license
   - `professional_yearly` - Professional yearly
   - `enterprise` - Enterprise license
   - `enterprise_yearly` - Enterprise yearly
4. **Set expiration date** in YYYY-MM-DD format
5. **Add notes** (optional) - Internal notes about the license
6. **Click "Create License"**

### **What Happens After Creation**
- ✅ License is generated with a unique key
- ✅ License is stored in Firebase Firestore
- ✅ License key is displayed in the results
- ✅ Customer can use the license key to activate

### **Important Notes**
- **Save the license key** - You'll need to send it to the customer
- **Email notification** - You may want to manually email the license key
- **No automatic billing** - Manual licenses don't create Stripe charges
- **Same validation** - Manual licenses work exactly like purchased ones

## 🔒 **License Revocation**

### **When to Revoke a License**
- **Customer request** - Customer wants to cancel
- **Payment issues** - Customer stopped paying
- **Terms violation** - Customer violated license terms
- **Technical issues** - License is causing problems
- **Fraud prevention** - Suspected fraudulent use

### **How to Revoke a License**

#### **Method 1: Using License ID**
1. **Go to "Revoke License" tab**
2. **Enter the License ID** (you can get this from the admin dashboard)
3. **Enter revocation reason**
4. **Click "Revoke License"**

#### **Method 2: Using Email Search**
1. **Go to "Revoke License" tab**
2. **Enter customer email** in the search field
3. **Click "Search"** - This will find the license and auto-fill the License ID
4. **Enter revocation reason**
5. **Click "Revoke License"**

### **What Happens After Revocation**
- ✅ License is marked as revoked in Firebase
- ✅ License is deactivated (cannot be used)
- ✅ Machine binding is removed
- ✅ Revocation reason is recorded
- ✅ Timestamp is added for audit trail

### **Important Notes**
- **Immediate effect** - Revocation takes effect immediately
- **Cannot be undone** - Revoked licenses cannot be reactivated
- **Customer notification** - You may want to notify the customer
- **Audit trail** - All revocations are logged with reasons

## 🔍 **Finding Licenses**

### **Using the GUI**
1. **Go to "License Management" tab**
2. **Enter customer email** in the search field
3. **Click "Search Licenses"**
4. **View license details** in the results table

### **Using the Web Interface**
1. **Go to** `https://your-app-name.onrender.com/admin`
2. **Enter your admin key**
3. **Use "Look Up License by Email"**
4. **Copy license keys** as needed

## 📊 **License Types and Pricing**

| Type | Duration | Price | Use Case |
|------|----------|-------|----------|
| `student` | 365 days | $49/year | Students and academics |
| `startup` | 30 days | $99/month | Small businesses |
| `professional` | 30 days | $199/month | Professional users |
| `professional_yearly` | 365 days | $1,999/year | Professional yearly |
| `enterprise` | 30 days | $499/month | Large organizations |
| `enterprise_yearly` | 365 days | $4,999/year | Enterprise yearly |

## 🛠️ **API Endpoints**

### **Manual License Creation**
```http
POST /admin/create-license
Content-Type: application/json
x-app-secret: YOUR_ADMIN_SECRET

{
  "email": "customer@example.com",
  "productType": "professional",
  "durationDays": 365,
  "notes": "Free trial for potential customer"
}
```

### **License Revocation**
```http
POST /admin/revoke-license
Content-Type: application/json
x-app-secret: YOUR_ADMIN_SECRET

{
  "licenseId": "abc123def456",
  "reason": "Customer requested cancellation"
}
```

### **Search Licenses**
```http
POST /admin/search-license
Content-Type: application/json
x-app-secret: YOUR_ADMIN_SECRET

{
  "searchTerm": "customer@example.com"
}
```

## 📝 **Best Practices**

### **Manual License Creation**
- **Always add notes** explaining why the license was created
- **Set appropriate expiration dates** - don't create perpetual licenses
- **Use consistent naming** for license types
- **Keep records** of manual licenses for accounting

### **License Revocation**
- **Always provide a reason** for revocation
- **Notify customers** before revoking (unless for fraud)
- **Keep revocation records** for customer service
- **Consider refunds** for recent purchases

### **General Management**
- **Regular audits** - Review licenses periodically
- **Customer communication** - Keep customers informed
- **Documentation** - Record all manual actions
- **Backup procedures** - Ensure data is backed up

## 🚨 **Important Considerations**

### **Manual vs. Stripe Licenses**
- **Manual licenses** don't create Stripe charges
- **Stripe licenses** are automatically created via webhooks
- **Both types** use the same validation system
- **Both types** can be revoked the same way

### **Customer Experience**
- **Manual licenses** require you to send the license key
- **Stripe licenses** are automatically emailed
- **Revocation** affects both types immediately
- **Activation** works the same for both types

### **Accounting and Billing**
- **Manual licenses** may need separate billing
- **Stripe licenses** are automatically billed
- **Revocation** doesn't automatically refund Stripe charges
- **Consider refunds** for revoked Stripe licenses

## 🆘 **Troubleshooting**

### **Can't Create License**
- Check your admin key is correct
- Verify the email format is valid
- Ensure expiration date is in the future
- Check your Render service is running

### **Can't Revoke License**
- Verify the License ID is correct
- Check the license exists in Firebase
- Ensure your admin key is valid
- Try searching by email first

### **Can't Find License**
- Check the email address is correct
- Try different search terms
- Verify the license exists in Firebase
- Check your admin key permissions

## 📞 **Support**

If you need help:
1. **Check the logs** in your Render dashboard
2. **Verify Firebase** has the license data
3. **Test with the web interface** first
4. **Check your admin key** is correct

---

*This system gives you complete control over license management while maintaining the security and validation of your existing system.*
