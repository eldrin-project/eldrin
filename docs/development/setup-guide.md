# Eldrin Platform Setup Guide

Welcome to Eldrin! This guide will walk you through setting up your own business platform from start to finish. No technical expertise required.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Step 1: Create Your Cloudflare Account](#step-1-create-your-cloudflare-account)
4. [Step 2: Launch the Setup Wizard](#step-2-launch-the-setup-wizard)
5. [Step 3: Connect Your Cloudflare Account](#step-3-connect-your-cloudflare-account)
6. [Step 4: Configure Your Company](#step-4-configure-your-company)
7. [Step 5: Select Your Apps](#step-5-select-your-apps)
8. [Step 6: Set Up Users & Roles](#step-6-set-up-users--roles)
9. [Step 7: Configure Integrations](#step-7-configure-integrations)
10. [Step 8: Review & Deploy](#step-8-review--deploy)
11. [Step 9: First Login](#step-9-first-login)
12. [Next Steps](#next-steps)

---

## Overview

Eldrin is a modular business platform that runs on your own Cloudflare account. This means:

- **You own your data** - Everything is stored in your Cloudflare account
- **You control costs** - Pay Cloudflare directly based on usage
- **You choose features** - Install only the apps you need
- **No vendor lock-in** - Export your data anytime

### How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR CLOUDFLARE ACCOUNT                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   ELDRIN PLATFORM                        ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       ││
│  │  │ Catalog │ │   CRM   │ │Invoicing│ │  More   │       ││
│  │  │   App   │ │   App   │ │   App   │ │  Apps   │       ││
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘       ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  D1 Database │  │  R2 Storage  │  │   Workers    │       │
│  │  (Your Data) │  │ (Your Files) │  │  (Your App)  │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### Estimated Setup Time

| Step | Time |
|------|------|
| Create Cloudflare account | 5 minutes |
| Setup wizard | 15-20 minutes |
| **Total** | **20-25 minutes** |

---

## Prerequisites

Before you begin, make sure you have:

- [ ] A valid email address
- [ ] A credit/debit card (for Cloudflare billing)
- [ ] Your company information (name, address, tax ID)
- [ ] Your custom domain (optional, but recommended)

### Cloudflare Pricing

Eldrin runs on Cloudflare's infrastructure. Typical costs:

| Tier | Monthly Cost | Best For |
|------|--------------|----------|
| Free | $0 | Testing and evaluation |
| Pro | ~$20-50 | Small businesses (1-10 users) |
| Business | ~$50-200 | Medium businesses (10-50 users) |
| Enterprise | Custom | Large organizations (50+ users) |

*Actual costs depend on usage (storage, requests, users)*

---

## Step 1: Create Your Cloudflare Account

### 1.1 Sign Up for Cloudflare

1. Go to [cloudflare.com](https://cloudflare.com)
2. Click **Sign Up**
3. Enter your email and create a password
4. Verify your email address

### 1.2 Add Payment Method

1. Go to **Billing** in your Cloudflare dashboard
2. Click **Add Payment Method**
3. Enter your credit card details
4. Click **Save**

> **Note**: You won't be charged until you exceed free tier limits.

### 1.3 Create an API Token

The Eldrin Setup Wizard needs permission to deploy resources to your account.

1. Go to **My Profile** → **API Tokens**
2. Click **Create Token**
3. Select **Create Custom Token**
4. Configure the token:

**Token Name:** `Eldrin Setup`

**Permissions (Account level):**

| Permission | Access Level |
|------------|--------------|
| D1 | Edit |
| Workers KV Storage | Edit |
| Workers R2 Storage | Edit |
| Workers Scripts | Edit |
| Cloudflare Pages | Edit |

**Additional Permissions (Zone level - only if using custom domain):**

| Permission | Access Level |
|------------|--------------|
| DNS | Edit |

**Account Resources:** Include → Your Account (or "All accounts")

**Zone Resources:** Include → All zones (or select specific zone for custom domain)

5. Click **Continue to Summary**
6. Review the permissions - you should see 5-6 permissions listed
7. Click **Create Token**
8. **Copy and save your token** - you'll need it in the next step

```
┌─────────────────────────────────────────────────────────────┐
│  ✓ Token Created Successfully                                │
│                                                              │
│  Your API token:                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx            │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  [ Copy ]                                                   │
│                                                              │
│  ⚠️  This token will only be shown once.                     │
│     Store it securely before closing this page.             │
└─────────────────────────────────────────────────────────────┘
```

> **Important**: Store this token securely. You won't be able to see it again.

---

## Step 2: Launch the Setup Wizard

### 2.1 Access the Wizard

Go to: **[setup.eldrin.app](https://setup.eldrin.app)**

You'll see the welcome screen:

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│                    Welcome to Eldrin                         │
│                                                              │
│     The modular business platform you own and control        │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                                                      │    │
│  │              [ Start Setup Wizard ]                  │    │
│  │                                                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│         Already have an account? [Sign In]                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Create Your Eldrin Account

1. Click **Start Setup Wizard**
2. Enter your details:
   - Email address
   - Password
   - Full name
3. Accept the Terms of Service
4. Click **Create Account**

---

## Step 3: Connect Your Cloudflare Account

### 3.1 Enter Your API Token

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1 of 8: Connect Cloudflare                             │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Enter your Cloudflare API Token                             │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ ●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  [?] How do I get an API token?                              │
│                                                              │
│                              [ Verify Connection ]           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

1. Paste your Cloudflare API token
2. Click **Verify Connection**

### 3.2 Connection Verified

The wizard will verify your token has the correct permissions:

```
┌─────────────────────────────────────────────────────────────┐
│  ✓ Connection Successful                                     │
│                                                              │
│  Account: Acme Corporation                                   │
│  Account ID: abc123...                                       │
│                                                              │
│  Permissions verified:                                       │
│  ✓ D1                    ✓ Workers Scripts                  │
│  ✓ Workers KV Storage    ✓ Workers R2 Storage               │
│  ✓ Cloudflare Pages      ○ DNS (optional, for custom domain)│
│                                                              │
│                                        [ Continue ]          │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 4: Configure Your Company

### 4.1 Company Information

```
┌─────────────────────────────────────────────────────────────┐
│  Step 2 of 8: Company Setup                                  │
│  ━━━━━━━━●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Tell us about your company                                  │
│                                                              │
│  Company Name *                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Acme Corporation                                     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Industry *                                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Manufacturing                                    ▼   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Company Size *                                              │
│  ○ 1-10 employees                                           │
│  ● 11-50 employees                                          │
│  ○ 51-200 employees                                         │
│  ○ 200+ employees                                           │
│                                                              │
│  Country *                                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ United States                                    ▼   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  [ Back ]                                  [ Continue ]      │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Business Address

```
┌─────────────────────────────────────────────────────────────┐
│  Business Address                                            │
│                                                              │
│  Street Address *                                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 123 Business Street                                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  City *                    State *         ZIP *            │
│  ┌─────────────────┐      ┌─────────┐     ┌──────────┐     │
│  │ San Francisco   │      │ CA   ▼  │     │ 94102    │     │
│  └─────────────────┘      └─────────┘     └──────────┘     │
│                                                              │
│  Tax ID / VAT Number (optional)                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 12-3456789                                           │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 Platform URL

Choose how users will access your platform:

```
┌─────────────────────────────────────────────────────────────┐
│  Platform URL                                                │
│                                                              │
│  How would you like to access your platform?                 │
│                                                              │
│  ● Use Eldrin subdomain (free)                              │
│    ┌─────────────────────────────────────────────────────┐  │
│    │ acme                        │.eldrin.app            │  │
│    └─────────────────────────────────────────────────────┘  │
│    Your URL: https://acme.eldrin.app                        │
│                                                              │
│  ○ Use my own domain                                        │
│    ┌─────────────────────────────────────────────────────┐  │
│    │ erp.acmecorp.com                                    │  │
│    └─────────────────────────────────────────────────────┘  │
│    Requires DNS configuration (we'll guide you)             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 5: Select Your Apps

### 5.1 Choose Your Starting Apps

Based on your industry and company size, we recommend certain apps. You can always add more later.

```
┌─────────────────────────────────────────────────────────────┐
│  Step 3 of 8: Select Apps                                    │
│  ━━━━━━━━━━━━●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Recommended for Manufacturing (11-50 employees)             │
│                                                              │
│  CORE APPS (Required)                                        │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ ☑ Catalog        Product and inventory management       ││
│  │ ☑ CRM            Customer relationship management       ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  RECOMMENDED APPS                                            │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ ☑ Invoicing      Create and manage invoices             ││
│  │ ☑ Orders         Order management and fulfillment       ││
│  │ ☑ Inventory      Advanced inventory tracking            ││
│  │ ☐ Manufacturing  Work orders and production             ││
│  │ ☐ Purchasing     Purchase orders and suppliers          ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  [ View All Apps ]                                          │
│                                                              │
│  Selected: 5 apps                    [ Back ] [ Continue ]   │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Browse All Apps (Optional)

Click "View All Apps" to see the complete catalog:

```
┌─────────────────────────────────────────────────────────────┐
│  All Available Apps                              [ Close X ] │
│                                                              │
│  Filter: [ All ▼ ]  Search: [                    🔍]        │
│                                                              │
│  COMMERCE                                                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │   Catalog    │ │  Invoicing   │ │    Orders    │        │
│  │   ☑ Added    │ │   ☑ Added    │ │   ☑ Added    │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│  ┌──────────────┐ ┌──────────────┐                         │
│  │ B2B E-Comm   │ │ Quotes/CPQ   │                         │
│  │   [ Add ]    │ │   [ Add ]    │                         │
│  └──────────────┘ └──────────────┘                         │
│                                                              │
│  FINANCE                                                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ General      │ │  Accounts    │ │  Accounts    │        │
│  │ Ledger       │ │  Payable     │ │  Receivable  │        │
│  │   [ Add ]    │ │   [ Add ]    │ │   [ Add ]    │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│                                                              │
│  ... more categories ...                                     │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 App Dependencies

If you select an app that requires another app, we'll let you know:

```
┌─────────────────────────────────────────────────────────────┐
│  ℹ️  Manufacturing requires additional apps                  │
│                                                              │
│  The Manufacturing app requires:                             │
│  • Bill of Materials (BOM)                                  │
│  • Inventory                                                │
│                                                              │
│  [ Add Required Apps ]        [ Cancel ]                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 6: Set Up Users & Roles

### 6.1 Create Administrator Account

Your first user is the Administrator with full access.

```
┌─────────────────────────────────────────────────────────────┐
│  Step 4 of 8: Users & Roles                                  │
│  ━━━━━━━━━━━━━━━━●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Administrator Account                                       │
│                                                              │
│  This will be the primary admin for your platform.          │
│                                                              │
│  Full Name *                                                 │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ John Smith                                           │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Email *                                                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ john.smith@acmecorp.com                              │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Password *                                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ ●●●●●●●●●●●●●●●●                                    │    │
│  └─────────────────────────────────────────────────────┘    │
│  ✓ 8+ characters  ✓ Number  ✓ Special character            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Invite Team Members (Optional)

Add team members now or later:

```
┌─────────────────────────────────────────────────────────────┐
│  Invite Team Members                                         │
│                                                              │
│  Add people who will use the platform. They'll receive      │
│  email invitations after deployment.                         │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ Email                    │ Role                    │ X  ││
│  ├─────────────────────────────────────────────────────────┤│
│  │ jane.doe@acmecorp.com    │ Sales Manager        ▼ │ 🗑  ││
│  │ bob.wilson@acmecorp.com  │ Warehouse Staff      ▼ │ 🗑  ││
│  │ sarah.jones@acmecorp.com │ Accountant           ▼ │ 🗑  ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  [ + Add Another Person ]                                   │
│                                                              │
│  ○ Skip for now - I'll add users later                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 Configure Roles

Define what each role can access:

```
┌─────────────────────────────────────────────────────────────┐
│  Role Permissions                                            │
│                                                              │
│  Sales Manager                                      [ Edit ] │
│  ├─ CRM: Full Access                                        │
│  ├─ Catalog: View Only                                      │
│  ├─ Orders: Full Access                                     │
│  ├─ Invoicing: Create & View                                │
│  └─ Inventory: View Only                                    │
│                                                              │
│  Warehouse Staff                                    [ Edit ] │
│  ├─ Inventory: Full Access                                  │
│  ├─ Orders: View & Update Status                            │
│  └─ Catalog: View Only                                      │
│                                                              │
│  Accountant                                         [ Edit ] │
│  ├─ Invoicing: Full Access                                  │
│  ├─ Orders: View Only                                       │
│  └─ Reports: Full Access                                    │
│                                                              │
│  [ + Create Custom Role ]                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 7: Configure Integrations

### 7.1 Email Settings

Configure how Eldrin sends emails (invoices, notifications, etc.)

```
┌─────────────────────────────────────────────────────────────┐
│  Step 5 of 8: Integrations                                   │
│  ━━━━━━━━━━━━━━━━━━━━●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Email Configuration                                         │
│                                                              │
│  How should Eldrin send emails?                              │
│                                                              │
│  ● Use Eldrin Email (Recommended)                           │
│    Emails sent from: noreply@acme.eldrin.app                │
│    ✓ No setup required                                      │
│    ✓ Includes 1,000 emails/month free                       │
│                                                              │
│  ○ Use my own email service                                 │
│    Connect your SMTP server or email provider               │
│    Supported: SendGrid, Mailgun, Amazon SES, Custom SMTP    │
│                                                              │
│  ○ Configure later                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Payment Processing (Optional)

If you're using Invoicing or B2B E-Commerce:

```
┌─────────────────────────────────────────────────────────────┐
│  Payment Processing                                          │
│                                                              │
│  Accept online payments from your customers.                 │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  💳 Stripe                              [ Connect ]     ││
│  │  Accept cards, ACH, and 135+ currencies                 ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  🅿️ PayPal                              [ Connect ]     ││
│  │  Accept PayPal and card payments                        ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ○ Skip - I'll accept payments outside the platform         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 Import Existing Data (Optional)

Bring your existing data into Eldrin:

```
┌─────────────────────────────────────────────────────────────┐
│  Import Data                                                 │
│                                                              │
│  Have existing data? Import it now or after setup.          │
│                                                              │
│  Available Imports:                                          │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 📦 Products           Upload CSV    [ Choose File ]     ││
│  │    Import your product catalog                          ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 👥 Customers          Upload CSV    [ Choose File ]     ││
│  │    Import your customer list                            ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 🏭 Suppliers          Upload CSV    [ Choose File ]     ││
│  │    Import your supplier list                            ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  [ Download Import Templates ]                              │
│                                                              │
│  ○ Skip - I'll start fresh                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 8: Review & Deploy

### 8.1 Review Your Configuration

```
┌─────────────────────────────────────────────────────────────┐
│  Step 6 of 8: Review & Deploy                                │
│  ━━━━━━━━━━━━━━━━━━━━━━━━●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Please review your configuration before deploying.          │
│                                                              │
│  COMPANY                                            [ Edit ] │
│  ├─ Name: Acme Corporation                                  │
│  ├─ Industry: Manufacturing                                 │
│  ├─ Location: San Francisco, CA                             │
│  └─ URL: https://acme.eldrin.app                            │
│                                                              │
│  APPS (5 selected)                                  [ Edit ] │
│  ├─ Catalog                                                 │
│  ├─ CRM                                                     │
│  ├─ Invoicing                                               │
│  ├─ Orders                                                  │
│  └─ Inventory                                               │
│                                                              │
│  USERS (4 users)                                    [ Edit ] │
│  ├─ John Smith (Administrator)                              │
│  ├─ Jane Doe (Sales Manager)                                │
│  ├─ Bob Wilson (Warehouse Staff)                            │
│  └─ Sarah Jones (Accountant)                                │
│                                                              │
│  INTEGRATIONS                                       [ Edit ] │
│  ├─ Email: Eldrin Email                                     │
│  ├─ Payments: Stripe (connected)                            │
│  └─ Data Import: Products (150 items)                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Estimated Costs

```
┌─────────────────────────────────────────────────────────────┐
│  Estimated Monthly Costs                                     │
│                                                              │
│  Based on your configuration and expected usage:             │
│                                                              │
│  Cloudflare Workers       $5.00/month                       │
│  D1 Database              $5.00/month (estimated)           │
│  R2 Storage               $0.00 (under free tier)           │
│  Email                    $0.00 (under free tier)           │
│  ─────────────────────────────────────────────────          │
│  Estimated Total          ~$10/month                        │
│                                                              │
│  ℹ️  Costs scale with usage. Most small businesses stay     │
│     under $50/month. View detailed pricing →                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 8.3 Deploy

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│  Ready to deploy your platform?                              │
│                                                              │
│  This will:                                                  │
│  • Create databases in your Cloudflare account              │
│  • Deploy the Eldrin platform and selected apps             │
│  • Set up your users and send invitation emails             │
│  • Import any data you uploaded                             │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                                                      │    │
│  │              [ 🚀 Deploy Platform ]                  │    │
│  │                                                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Deployment takes 2-5 minutes.                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 8.4 Deployment Progress

```
┌─────────────────────────────────────────────────────────────┐
│  Deploying Your Platform                                     │
│                                                              │
│  ████████████████████████░░░░░░░░░░  65%                    │
│                                                              │
│  ✓ Creating D1 databases                                    │
│  ✓ Setting up R2 storage buckets                            │
│  ✓ Deploying Eldrin Shell                                   │
│  ● Deploying Catalog app...                                 │
│  ○ Deploying CRM app                                        │
│  ○ Deploying Invoicing app                                  │
│  ○ Deploying Orders app                                     │
│  ○ Deploying Inventory app                                  │
│  ○ Configuring users and permissions                        │
│  ○ Importing data                                           │
│  ○ Final verification                                       │
│                                                              │
│  Please don't close this window.                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 8.5 Deployment Complete

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│                    🎉 Congratulations!                       │
│                                                              │
│          Your Eldrin platform is ready to use.              │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                                                      │    │
│  │  Your platform URL:                                  │    │
│  │  https://acme.eldrin.app                            │    │
│  │                                                      │    │
│  │  [ Copy Link ]                                      │    │
│  │                                                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  We've sent login instructions to:                          │
│  • john.smith@acmecorp.com (Administrator)                  │
│  • jane.doe@acmecorp.com                                    │
│  • bob.wilson@acmecorp.com                                  │
│  • sarah.jones@acmecorp.com                                 │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                                                      │    │
│  │              [ Go to Your Platform → ]               │    │
│  │                                                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 9: First Login

### 9.1 Access Your Platform

1. Go to your platform URL (e.g., https://acme.eldrin.app)
2. Enter your admin email and password
3. Click **Sign In**

### 9.2 Welcome Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│  🏠 Dashboard                           John Smith ▼  🔔  ⚙️ │
├─────────┬───────────────────────────────────────────────────┤
│         │                                                    │
│ 📦 Catalog │  Welcome to Eldrin, John!                       │
│ 👥 CRM     │                                                 │
│ 📋 Orders  │  ┌─────────────────────────────────────────┐   │
│ 💰 Invoice │  │  🚀 Getting Started                      │   │
│ 📊 Inventory│  │                                          │   │
│         │  │  Complete these steps to set up your       │   │
│         │  │  business:                                  │   │
│         │  │                                          │   │
│         │  │  ☑ Create your account                    │   │
│         │  │  ☐ Add your first product                 │   │
│         │  │  ☐ Add your first customer                │   │
│         │  │  ☐ Create your first invoice              │   │
│         │  │                                          │   │
│         │  │  [ Continue Setup → ]                     │   │
│         │  │                                          │   │
│         │  └─────────────────────────────────────────┘   │
│         │                                                    │
│ ─────── │  Quick Stats                                       │
│ ⚙️ Settings │  ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│         │  │ Products │ │ Customers│ │  Orders  │       │
│         │  │   150    │ │    0     │ │    0     │       │
│         │  └──────────┘ └──────────┘ └──────────┘       │
│         │                                                    │
└─────────┴───────────────────────────────────────────────────┘
```

### 9.3 Complete the Getting Started Checklist

The platform guides you through essential first steps:

1. **Add your first product** - Enter a product in the Catalog
2. **Add your first customer** - Create a customer in CRM
3. **Create your first invoice** - Generate an invoice
4. **Customize your settings** - Add your logo, configure preferences

---

## Next Steps

### Recommended Actions

| Action | Description |
|--------|-------------|
| **Complete Getting Started** | Follow the in-app checklist to set up basics |
| **Import remaining data** | Upload any additional products, customers, or suppliers |
| **Train your team** | Share the user guide with your team members |
| **Customize settings** | Configure tax rates, payment terms, email templates |
| **Set up backups** | Enable automatic data backups in Settings |

### Getting Help

| Resource | Description |
|----------|-------------|
| **In-App Help** | Click the `?` icon in any screen for contextual help |
| **Documentation** | [docs.eldrin.app](https://docs.eldrin.app) |
| **Video Tutorials** | [youtube.com/@eldrin](https://youtube.com/@eldrin) |
| **Community Forum** | [community.eldrin.app](https://community.eldrin.app) |
| **Email Support** | support@eldrin.app |

### Adding More Apps

Need additional functionality? Add apps anytime:

1. Go to **Settings** → **Apps**
2. Click **Browse Apps**
3. Select the app you want to add
4. Click **Install**

Popular additions:
- **Manufacturing** - For production management
- **General Ledger** - For full accounting
- **B2B E-Commerce** - For customer self-service portal

---

## Appendix A: Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Can't connect Cloudflare | Verify your API token has all required permissions (D1, Workers KV Storage, Workers R2 Storage, Workers Scripts, Cloudflare Pages) |
| Missing permissions | Create a new token with Edit access to all required services |
| Deployment failed | Check Cloudflare dashboard for errors, try redeploying |
| Email not received | Check spam folder, verify email address |
| Can't access platform | Clear browser cache, try incognito mode |
| Custom domain not working | Ensure DNS permission (Zone level) is included in your token |

### Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| `INVALID_TOKEN` | API token is incorrect or expired | Create a new token with correct permissions |
| `MISSING_PERMISSION_D1` | Token lacks D1 access | Edit token to add D1: Edit permission |
| `MISSING_PERMISSION_R2` | Token lacks R2 access | Edit token to add Workers R2 Storage: Edit permission |
| `MISSING_PERMISSION_KV` | Token lacks KV access | Edit token to add Workers KV Storage: Edit permission |
| `MISSING_PERMISSION_WORKERS` | Token lacks Workers access | Edit token to add Workers Scripts: Edit permission |
| `QUOTA_EXCEEDED` | Cloudflare resource limit reached | Upgrade your Cloudflare plan or delete unused resources |
| `DEPLOYMENT_FAILED` | Something went wrong during deployment | Check error details, retry, or contact support with deployment ID |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **Cloudflare** | The cloud platform that hosts your Eldrin instance |
| **D1** | Cloudflare's serverless SQL database where your data is stored |
| **Workers R2 Storage** | Cloudflare's object storage for documents, images, and files |
| **Workers KV Storage** | Cloudflare's key-value storage for sessions and cache |
| **Workers Scripts** | Cloudflare's serverless compute platform that runs Eldrin |
| **Cloudflare Pages** | Cloudflare's platform for hosting the Eldrin frontend |
| **API Token** | A security key that lets the Setup Wizard deploy to your Cloudflare account |
| **App** | A module that adds functionality (CRM, Invoicing, etc.) |
| **Shell** | The core Eldrin platform that orchestrates all apps |
| **DNS** | Zone-level permission for managing domain records (only needed for custom domains) |

---

*Last updated: December 2025*
*Version: 1.0*
