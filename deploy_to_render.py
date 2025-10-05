#!/usr/bin/env python3
"""
Render Deployment Helper Script
Helps configure and deploy the CONFIRM License System to Render
"""

import os
import sys
import subprocess
import json
import secrets
import string
from pathlib import Path

def generate_secret(length=32):
    """Generate a secure random secret"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def check_git_status():
    """Check if we're in a git repository and if there are uncommitted changes"""
    try:
        # Check if we're in a git repository
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, text=True, check=True)
        
        if result.stdout.strip():
            print("⚠️  Warning: You have uncommitted changes:")
            print(result.stdout)
            response = input("Do you want to continue? (y/N): ").strip().lower()
            if response != 'y':
                print("Deployment cancelled.")
                return False
        
        # Check if we're on main branch
        result = subprocess.run(['git', 'branch', '--show-current'], 
                              capture_output=True, text=True, check=True)
        current_branch = result.stdout.strip()
        
        if current_branch != 'main':
            print(f"⚠️  Warning: You're on branch '{current_branch}', not 'main'")
            response = input("Do you want to continue? (y/N): ").strip().lower()
            if response != 'y':
                print("Deployment cancelled.")
                return False
        
        return True
        
    except subprocess.CalledProcessError:
        print("❌ Error: Not in a git repository or git not available")
        return False
    except FileNotFoundError:
        print("❌ Error: Git not found. Please install Git first.")
        return False

def create_env_file():
    """Create a .env file with generated secrets and user input"""
    print("\n🔧 Setting up environment configuration...")
    
    # Check if .env already exists
    if os.path.exists('.env'):
        response = input("⚠️  .env file already exists. Overwrite? (y/N): ").strip().lower()
        if response != 'y':
            print("Keeping existing .env file.")
            return True
    
    print("\n📝 Please provide the following information:")
    print("(Press Enter to skip optional fields)")
    
    # Generate secrets
    shared_secret = generate_secret()
    license_secret = generate_secret()
    
    print(f"\n✅ Generated SHARED_SECRET: {shared_secret}")
    print(f"✅ Generated LICENSE_SECRET: {license_secret}")
    
    # Get user input
    stripe_secret = input("Stripe Secret Key (sk_test_...): ").strip()
    stripe_webhook = input("Stripe Webhook Secret (whsec_...): ").strip()
    sendgrid_key = input("SendGrid API Key (SG...): ").strip()
    
    # Firebase configuration
    print("\n🔥 Firebase Configuration:")
    firebase_project = input("Firebase Project ID: ").strip()
    firebase_email = input("Firebase Service Account Email: ").strip()
    firebase_private_key = input("Firebase Private Key (full key with \\n): ").strip()
    
    # Create .env content
    env_content = f"""# CONFIRM License System Environment Configuration
# Generated on {os.popen('date').read().strip()}

# Core Configuration
SHARED_SECRET={shared_secret}
LICENSE_SECRET={license_secret}
NODE_ENV=production
PORT=3000

# Stripe Configuration
STRIPE_SECRET_KEY={stripe_secret}
STRIPE_WEBHOOK_SECRET={stripe_webhook}

# SendGrid Configuration
SENDGRID_API_KEY={sendgrid_key}

# Firebase Configuration
type=service_account
project_id={firebase_project}
private_key_id=your_private_key_id
private_key={firebase_private_key}
client_email={firebase_email}
client_id=your_client_id
auth_uri=https://accounts.google.com/o/oauth2/auth
token_uri=https://oauth2.googleapis.com/token
auth_provider_x509_cert_url=https://www.googleapis.com/oauth2/v1/certs
client_x509_cert_url=https://www.googleapis.com/robot/v1/metadata/x509/{firebase_email.replace('@', '%40')}
universe_domain=googleapis.com

# Stripe Price IDs (update these with your actual price IDs)
STRIPE_PRICE_ID_STUDENT_YEAR=price_student_yearly
STRIPE_PRICE_ID_STARTUP_MONTH=price_startup_monthly
STRIPE_PRICE_ID_PRO_MONTH=price_pro_monthly
STRIPE_PRICE_ID_PRO_YEAR=price_pro_yearly
STRIPE_PRICE_ID_ENTERPRISE_MONTH=price_enterprise_monthly
STRIPE_PRICE_ID_ENTERPRISE_YEAR=price_enterprise_yearly
STRIPE_PRICE_ID_INTEGRATION=price_integration_yearly
STRIPE_PRICE_ID_WHITELABEL=price_whitelabel_yearly

# Client Configuration (update after deployment)
LICENSE_API_URL=https://render-confirmlicense.onrender.com
ADMIN_SECRET_KEY={shared_secret}
"""
    
    # Write .env file
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("\n✅ Environment configuration saved to .env")
    return True

def commit_changes():
    """Commit current changes to git"""
    try:
        print("\n📝 Committing changes to git...")
        
        # Add all files
        subprocess.run(['git', 'add', '.'], check=True)
        
        # Commit
        commit_message = "Deploy to Render: Add deployment configuration"
        subprocess.run(['git', 'commit', '-m', commit_message], check=True)
        
        print("✅ Changes committed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error committing changes: {e}")
        return False

def push_to_github():
    """Push changes to GitHub"""
    try:
        print("\n🚀 Pushing to GitHub...")
        subprocess.run(['git', 'push', 'origin', 'main'], check=True)
        print("✅ Changes pushed to GitHub successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error pushing to GitHub: {e}")
        return False

def show_deployment_instructions():
    """Show instructions for completing the deployment"""
    print("\n" + "="*60)
    print("🎯 DEPLOYMENT INSTRUCTIONS")
    print("="*60)
    
    print("\n1. 🌐 Go to Render Dashboard:")
    print("   https://dashboard.render.com")
    
    print("\n2. 🔗 Create New Web Service:")
    print("   - Click 'New' → 'Web Service'")
    print("   - Connect repository: 1yololomg1/render-confirmlicense")
    print("   - Use API key: rnd_2hdonGoimhH6CUxHasW1WcoCHU3Z")
    
    print("\n3. ⚙️  Configure Service:")
    print("   - Name: render-confirmlicense")
    print("   - Environment: Node")
    print("   - Build Command: npm install")
    print("   - Start Command: node server.mjs")
    print("   - Plan: Free")
    
    print("\n4. 🔐 Set Environment Variables:")
    print("   - Copy all variables from your .env file")
    print("   - Paste them into Render's Environment Variables section")
    print("   - Make sure to set all required variables")
    
    print("\n5. 🚀 Deploy:")
    print("   - Click 'Create Web Service'")
    print("   - Wait for deployment to complete")
    print("   - Your service will be at: https://render-confirmlicense.onrender.com")
    
    print("\n6. ✅ Test Deployment:")
    print("   - Visit: https://render-confirmlicense.onrender.com")
    print("   - Admin panel: https://render-confirmlicense.onrender.com/admin")
    print("   - Use your SHARED_SECRET as the admin key")
    
    print("\n📋 Your API Key: rnd_2hdonGoimhH6CUxHasW1WcoCHU3Z")
    print("📋 Repository: 1yololomg1/render-confirmlicense")
    print("📋 Deployment URL: https://render-confirmlicense.onrender.com")

def main():
    """Main deployment function"""
    print("🚀 CONFIRM License System - Render Deployment Helper")
    print("=" * 60)
    
    # Check git status
    if not check_git_status():
        return
    
    # Create environment file
    if not create_env_file():
        return
    
    # Ask if user wants to commit and push
    response = input("\n📝 Do you want to commit and push changes to GitHub? (y/N): ").strip().lower()
    if response == 'y':
        if commit_changes() and push_to_github():
            print("\n✅ All changes pushed to GitHub!")
        else:
            print("\n⚠️  Some errors occurred, but you can still proceed with manual deployment")
    
    # Show deployment instructions
    show_deployment_instructions()
    
    print("\n🎉 Setup complete! Follow the instructions above to deploy to Render.")

if __name__ == "__main__":
    main()