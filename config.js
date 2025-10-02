// CONFIRM License Server Configuration
// You can change these values here

export const CONFIG = {
  // Admin authentication secret
  SHARED_SECRET: "confirm-admin-secret-2024",
  
  // License signing secret
  LICENSE_SECRET: "confirm-license-secret-2024",
  
  // Server settings
  PORT: process.env.PORT || 3000,
  
  // Email settings
  FROM_EMAIL: "noreply@deltavsolutions.com",
  
  // App info
  APP_NAME: "CONFIRM Statistical Analysis Suite",
  COMPANY_NAME: "TraceSeis, Inc.",
  DIVISION: "deltaV solutions"
};

// You can also override with environment variables
export const getConfig = () => ({
  SHARED_SECRET: process.env.SHARED_SECRET || CONFIG.SHARED_SECRET,
  LICENSE_SECRET: process.env.LICENSE_SECRET || CONFIG.LICENSE_SECRET,
  PORT: process.env.PORT || CONFIG.PORT,
  FROM_EMAIL: process.env.FROM_EMAIL || CONFIG.FROM_EMAIL,
  APP_NAME: CONFIG.APP_NAME,
  COMPANY_NAME: CONFIG.COMPANY_NAME,
  DIVISION: CONFIG.DIVISION
});

