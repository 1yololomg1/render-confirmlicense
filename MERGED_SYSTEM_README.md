# CONFIRM License Management System - Merged Version

This is the merged system combining your working `render-confirmlicense` Node.js server with the Python GUI license management components.

## 🎯 **What You Have Now**

### **Backend (Node.js/Express)**
- **File**: `server.mjs`
- **Platform**: Render.com
- **Database**: Firebase Firestore
- **Payment**: Stripe integration
- **Email**: SendGrid integration
- **Features**: License generation, validation, activation, admin dashboard

### **Frontend (Python GUI)**
- **File**: `license_manager_gui.py`
- **Platform**: Desktop application
- **Features**: License management, verification, statistics, hardware detection

## 🚀 **Quick Start**

### **1. Install Dependencies**

```bash
# Install Node.js dependencies
npm install

# Install Python dependencies
pip install -r requirements.txt
```

### **2. Configure the System**

```bash
# Run the setup script
python setup_license_manager.py
```

**When prompted, enter:**
- **Render App URL**: `https://your-app-name.onrender.com` (no `/api` at the end)
- **Admin Key**: Your `SHARED_SECRET` from server.mjs

### **3. Deploy the Backend**

Deploy your `server.mjs` to Render.com with these environment variables:
- `SHARED_SECRET` - Your admin secret key
- `LICENSE_SECRET` - Your license signing secret
- `STRIPE_SECRET_KEY` - Your Stripe secret key
- `STRIPE_WEBHOOK_SECRET` - Your Stripe webhook secret
- `SENDGRID_API_KEY` - Your SendGrid API key
- Firebase service account credentials

### **4. Run the GUI**

```bash
python license_manager_gui.py
```

## 🌐 **Web Interface**

Access the web admin panel at:
```
https://your-app-name.onrender.com/admin
```

Use your `SHARED_SECRET` as the admin key.

## 📋 **Features**

### **Backend (server.mjs)**
- ✅ Stripe webhook processing
- ✅ License generation and validation
- ✅ Firebase Firestore integration
- ✅ Email notifications via SendGrid
- ✅ Admin dashboard web interface
- ✅ License activation and validation

### **Frontend (license_manager_gui.py)**
- ✅ System overview and statistics
- ✅ License search by email
- ✅ License verification with hardware detection
- ✅ Hardware information collection
- ✅ Pending licenses management
- ✅ Recent activity monitoring

## 🔧 **API Endpoints**

### **Public Endpoints**
- `POST /activate` - Activate a license on a machine
- `POST /validate` - Validate a license key
- `GET /` - Health check

### **Admin Endpoints** (require `x-app-secret` header)
- `GET /admin` - Web admin dashboard
- `GET /admin/recent-licenses` - Recent license activity
- `GET /admin/pending-licenses` - Pending (unactivated) licenses
- `POST /admin/lookup-email` - Look up license by email
- `POST /admin/approve-license` - Manually approve a license
- `POST /admin/create-license` - **NEW** - Create license manually
- `POST /admin/revoke-license` - **NEW** - Revoke existing license
- `POST /admin/search-license` - **NEW** - Search licenses by email

### **Webhook Endpoints**
- `POST /webhook` - Stripe webhook for payment processing

## 🎯 **License Types Supported**

Based on your Stripe configuration:
- **Student Annual**: $49/year (365 days)
- **Startup Monthly**: $99/month (30 days)
- **Professional Monthly**: $199/month (30 days)
- **Professional Annual**: $1,999/year (365 days)
- **Enterprise Monthly**: $499/month (30 days)
- **Enterprise Annual**: $4,999/year (365 days)
- **Integration Annual**: Custom pricing (365 days)
- **White-label Annual**: Custom pricing (365 days)

## 🔑 **Authentication**

All admin functions use your `SHARED_SECRET` environment variable:
- **Web Interface**: Enter the secret when prompted
- **API Calls**: Include `x-app-secret` header
- **GUI Application**: Enter the secret in the System Overview tab

## 📊 **Usage Examples**

### **1. View System Statistics**
1. Launch `python license_manager_gui.py`
2. Go to "System Overview" tab
3. Enter your admin key
4. Click "Load System Statistics"

### **2. Search for a License**
1. Go to "License Management" tab
2. Enter customer email address
3. Click "Search Licenses"

### **3. Verify a License**
1. Go to "Verify License" tab
2. Click "Get Current Hardware Info" (auto-detects hardware)
3. Enter a license key
4. Click "Verify License"

### **4. View Web Dashboard**
1. Go to `https://your-app-name.onrender.com/admin`
2. Enter your admin key
3. Use the web interface for quick lookups

## 🔧 **Configuration Files**

- `package.json` - Node.js dependencies
- `requirements.txt` - Python dependencies
- `license_manager_config.py` - GUI configuration
- `.env` - Environment variables (created by setup script)

## 🚨 **Important Notes**

### **What Works**
- ✅ License generation via Stripe webhooks
- ✅ License validation and activation
- ✅ Admin dashboard (web and GUI)
- ✅ Email notifications
- ✅ Hardware-based license binding

### **What's Now Available**
- ✅ **Manual License Creation** - Create licenses directly without Stripe
- ✅ **License Revocation** - Revoke existing licenses when needed
- ✅ **License Search** - Find licenses by email for management
- ✅ **Complete Admin Control** - Full license lifecycle management

### **New Features Added**
1. **Manual License Creation**: `/admin/create-license` endpoint
2. **License Revocation**: `/admin/revoke-license` endpoint  
3. **License Search**: `/admin/search-license` endpoint
4. **Enhanced GUI**: Updated interface for all new features

## 🆘 **Troubleshooting**

### **GUI Won't Connect**
- Check your Render app URL is correct
- Verify your admin key matches `SHARED_SECRET`
- Ensure your Render service is running

### **No Licenses Found**
- Check if you have licenses in Firebase
- Try the web interface first
- Verify your admin key is correct

### **Hardware Detection Failed**
- On Windows: Ensure `wmic` command is available
- Manual entry is always available
- Check system permissions

## 📞 **Support**

1. **Test Web Interface**: `https://your-app-name.onrender.com/admin`
2. **Check Render Dashboard**: Ensure service is running
3. **Verify Environment Variables**: Check all required variables are set
4. **Check Firebase**: Ensure database has data

## 🔄 **System Flow**

1. **Customer Purchase**: Stripe webhook triggers license creation
2. **License Generation**: Server creates license with hardware binding
3. **Email Notification**: Customer receives license key via SendGrid
4. **License Activation**: Customer activates license on their machine
5. **Validation**: System validates license on each use
6. **Admin Management**: You can view and manage licenses via GUI or web

---

*This merged system combines the best of both worlds: a robust backend for license management and a user-friendly GUI for administration.*
