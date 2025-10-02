#!/usr/bin/env python3
"""
License Manager Configuration
Simple configuration file for the license management GUI
"""

import os
from pathlib import Path

class LicenseManagerConfig:
    """Configuration settings for the License Manager GUI"""
    
    def __init__(self):
        # API Configuration - Update these with your actual values
        self.API_BASE_URL = os.getenv('LICENSE_API_URL', 'https://your-app-name.onrender.com')
        self.ADMIN_KEY = os.getenv('ADMIN_SECRET_KEY', '')
        
        # Application Settings
        self.APP_TITLE = "CONFIRM License Management System"
        self.APP_VERSION = "1.0.0"
        self.WINDOW_SIZE = "1200x800"
        
        # Security Settings
        self.REQUEST_TIMEOUT = 30  # seconds
        self.MAX_RETRIES = 3
        
        # UI Settings
        self.THEME_COLORS = {
            'primary': '#1a365d',
            'secondary': '#2b6cb0',
            'success': '#059669',
            'warning': '#d97706',
            'error': '#dc2626',
            'background': '#f8f9fa',
            'text': '#2d3748'
        }
        
        # License Types and Pricing
        self.LICENSE_TYPES = {
            'student': {'name': 'Student', 'price': '$49/year', 'duration_days': 365},
            'startup': {'name': 'Startup', 'price': '$99/month', 'duration_days': 30},
            'professional': {'name': 'Professional', 'price': '$199/month', 'duration_days': 30},
            'professional_yearly': {'name': 'Professional (Yearly)', 'price': '$1,999/year', 'duration_days': 365},
            'enterprise': {'name': 'Enterprise', 'price': '$499/month', 'duration_days': 30},
            'enterprise_yearly': {'name': 'Enterprise (Yearly)', 'price': '$4,999/year', 'duration_days': 365}
        }
        
        # Default settings
        self.DEFAULT_LICENSE_DURATION_DAYS = 365
        self.DEFAULT_LICENSE_TYPE = 'student'
        
        # File paths
        self.CONFIG_DIR = Path.home() / '.confirm_license_manager'
        self.LOG_FILE = self.CONFIG_DIR / 'license_manager.log'
        self.CACHE_FILE = self.CONFIG_DIR / 'cache.json'
        
        # Create config directory if it doesn't exist
        self.CONFIG_DIR.mkdir(exist_ok=True)
    
    def get_api_url(self, endpoint):
        """Get full API URL for an endpoint"""
        return f"{self.API_BASE_URL}/license-api?endpoint={endpoint}"
    
    def validate_config(self):
        """Validate configuration settings"""
        errors = []
        
        if not self.API_BASE_URL or self.API_BASE_URL == 'https://your-app-name.onrender.com/api':
            errors.append("API_BASE_URL must be set to your actual Render app URL")
        
        if not self.ADMIN_KEY:
            errors.append("ADMIN_SECRET_KEY must be set")
        
        return errors
    
    def save_config(self):
        """Save configuration to file"""
        config_data = {
            'api_base_url': self.API_BASE_URL,
            'admin_key': self.ADMIN_KEY,
            'app_title': self.APP_TITLE,
            'app_version': self.APP_VERSION
        }
        
        import json
        with open(self.CONFIG_DIR / 'config.json', 'w') as f:
            json.dump(config_data, f, indent=2)
    
    def load_config(self):
        """Load configuration from file"""
        config_file = self.CONFIG_DIR / 'config.json'
        if config_file.exists():
            import json
            with open(config_file, 'r') as f:
                config_data = json.load(f)
                self.API_BASE_URL = config_data.get('api_base_url', self.API_BASE_URL)
                self.ADMIN_KEY = config_data.get('admin_key', self.ADMIN_KEY)
                self.APP_TITLE = config_data.get('app_title', self.APP_TITLE)
                self.APP_VERSION = config_data.get('app_version', self.APP_VERSION)

# Global config instance
config = LicenseManagerConfig()

# Load existing config on import
config.load_config()
