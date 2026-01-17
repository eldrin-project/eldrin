# Eldrin Apps Roadmap

This document outlines the planned applications for the Eldrin platform, organized by business domain and implementation priority.

> **Note:** The Eldrin Shell (Core) provides user management, permissions, authentication, navigation, theming, and inter-app communication. Apps listed here are modular add-ons that extend the platform's functionality.

---

## Priority Legend

| Priority | Meaning |
|----------|---------|
| P0 | Foundation - First apps to build, minimal dependencies |
| P1 | Essential - Required for basic business operations |
| P2 | Growth - Scale and optimize operations |
| P3 | Enterprise - Advanced features for larger organizations |

---

## Summary by Domain

| Domain | Apps | Count |
|--------|------|-------|
| **Sales** | CRM, Quotes & CPQ, Orders, Invoicing, B2B E-Commerce, Subscription Management | 6 |
| **Product Management** | Catalog, Bill of Materials | 2 |
| **Supply Chain** | Inventory, Purchasing, Warehouse Management, Shipping, Returns/RMA, Demand Planning | 6 |
| **Manufacturing** | Manufacturing, Quality Management, MRP | 3 |
| **Finance** | General Ledger, Accounts Payable, Accounts Receivable, Fixed Assets, Budgeting, Tax Management, Expenses, Multi-Entity | 8 |
| **Customer Engagement** | Support/Helpdesk, Projects, Appointments, Email Marketing, Loyalty & Rewards, Field Service, Commissions | 7 |
| **Human Resources** | HRIS, Contracts | 2 |
| **Assets & Operations** | Fleet Management, Maintenance/CMMS, Rental Management | 3 |
| **Platform** | Documents, Workflow Engine, Audit & Compliance, Reporting & Analytics, Payments, EDI & Integrations | 6 |

**Total: 43 Apps**

---

## Summary by Priority

| Priority | Count | Apps |
|----------|-------|------|
| P0 | 4 | Catalog, CRM, General Ledger, Documents |
| P1 | 6 | Invoicing, Orders, Inventory, Accounts Payable, Accounts Receivable, Purchasing |
| P2 | 15 | BOM, Manufacturing, WMS, Quotes & CPQ, B2B E-Commerce, Payments, Reporting, Fixed Assets, Budgeting, Tax Management, Subscription Management, Returns/RMA, Field Service, Workflow Engine, Audit & Compliance |
| P3 | 18 | MRP, Quality Management, Demand Planning, Shipping, Projects, Appointments, Support/Helpdesk, Email Marketing, Loyalty & Rewards, Commissions, Contracts, Expenses, HRIS, Fleet Management, Maintenance/CMMS, Rental Management, EDI & Integrations, Multi-Entity |

---

## Sales

Applications for managing customer relationships, sales processes, and revenue generation.

### CRM (Customer Relationship Management)
**Priority:** P0 | **Dependencies:** None

Customer and contact management. Central hub for all customer interactions and data.

**Features:**
- Contact and company management
- Customer segmentation and tags
- Interaction history and notes
- Custom fields
- Activity timeline
- Lead tracking and pipeline
- Import/export contacts

**Hooks:** `getContactById`, `searchContacts`, `getCompanyById`, `addInteraction`, `getCustomerHistory`

---

### Quotes & CPQ (Configure-Price-Quote)
**Priority:** P2 | **Dependencies:** Catalog, CRM

Sales quoting with product configuration and pricing rules.

**Features:**
- Quote creation and management
- Product configuration rules
- Pricing rules and discounts
- Approval workflows
- Quote versioning
- Quote-to-order conversion
- E-signature integration
- Margin analysis

**Hooks:** `createQuote`, `configureProduct`, `calculatePrice`, `submitForApproval`, `convertToOrder`

**Events:** `quote:created`, `quote:approved`, `quote:converted`, `quote:expired`

---

### Orders
**Priority:** P1 | **Dependencies:** Catalog, CRM

Order management for sales transactions. Tracks order lifecycle from creation to fulfillment.

**Features:**
- Order creation and editing
- Order status workflow (draft → confirmed → processing → shipped → delivered)
- Order history per customer
- Shipping integration hooks
- Partial fulfillment support
- Returns and exchanges

**Hooks:** `createOrder`, `getOrderById`, `updateOrderStatus`, `getOrdersByCustomer`

**Events:** `order:created`, `order:confirmed`, `order:shipped`, `order:delivered`

---

### Invoicing
**Priority:** P1 | **Dependencies:** Catalog

Invoice creation, management, and tracking. Handles billing workflows and payment status.

**Features:**
- Invoice creation from catalog items
- Recurring invoices
- Payment tracking and reminders
- Tax calculation
- PDF generation and email delivery
- Credit notes and refunds
- Multi-currency support

**Hooks:** `createInvoice`, `getInvoiceById`, `getInvoicesByCustomer`, `recordPayment`, `sendReminder`

**Events:** `invoice:created`, `invoice:paid`, `invoice:overdue`

---

### B2B E-Commerce
**Priority:** P2 | **Dependencies:** Catalog, CRM, Invoicing, Orders

Self-service portal for B2B customers to browse catalog, place orders, and manage their account.

**Features:**
- Customer-specific pricing
- Bulk ordering
- Quick order (by SKU)
- Order history and reordering
- Quote requests
- Account management

**Hooks:** `getCustomerPricing`, `submitQuoteRequest`

---

### Subscription Management
**Priority:** P2 | **Dependencies:** Invoicing, Payments

Recurring billing, subscription lifecycle, and usage-based pricing.

**Features:**
- Subscription plan management
- Trial periods and conversions
- Proration calculations
- Plan upgrades/downgrades
- Usage metering and billing
- Renewal management
- Churn analysis
- Dunning for failed payments

**Hooks:** `createSubscription`, `changeSubscriptionPlan`, `cancelSubscription`, `recordUsage`

**Events:** `subscription:created`, `subscription:renewed`, `subscription:cancelled`, `subscription:churned`

---

## Product Management

Applications for managing products, services, and their structures.

### Catalog
**Priority:** P0 | **Dependencies:** None

Product and service catalog management. The foundation for inventory, pricing, and sales operations.

**Features:**
- Product CRUD with variants (size, color, etc.)
- Category and tag management
- Pricing tiers and rules
- Product images and media
- SKU and barcode management
- Import/export (CSV, Excel)

**Hooks:** `getProductById`, `searchProducts`, `getCategories`, `updateStock`

---

### Bill of Materials (BOM)
**Priority:** P2 | **Dependencies:** Catalog

Product structure and component management for manufacturing.

**Features:**
- Multi-level BOM structures
- BOM versioning and revisions
- Component substitutions
- Phantom/kit assemblies
- Where-used analysis
- Cost rollup calculations
- Engineering change management
- Yield and scrap factors

**Hooks:** `createBOM`, `getBOMById`, `explodeBOM`, `calculateCost`, `getWhereUsed`

**Events:** `bom:created`, `bom:revised`, `bom:obsoleted`

---

## Supply Chain

Applications for managing inventory, procurement, warehousing, and logistics.

### Inventory
**Priority:** P1 | **Dependencies:** Catalog

Advanced inventory management beyond basic stock levels.

**Features:**
- Multi-warehouse support
- Stock movements and transfers
- Batch/lot tracking
- Expiry date management
- Reorder points and alerts
- Stock valuation (FIFO, LIFO, average)
- Inventory adjustments and audits
- Barcode scanning support

**Hooks:** `getStockLevels`, `createStockMovement`, `getWarehouseStock`, `reserveInventory`

**Events:** `inventory:low`, `inventory:adjusted`, `inventory:transferred`

---

### Purchasing
**Priority:** P1 | **Dependencies:** Catalog, Inventory

Supplier management and purchase order creation.

**Features:**
- Supplier/vendor management
- Purchase order creation
- Goods receiving
- Supplier pricing and catalogs
- Purchase history and analytics
- Reorder automation

**Hooks:** `createPurchaseOrder`, `receiveGoods`, `getSupplierById`

**Events:** `purchase:ordered`, `purchase:received`

---

### Warehouse Management (WMS)
**Priority:** P2 | **Dependencies:** Inventory

Advanced warehouse operations including bin management and fulfillment optimization.

**Features:**
- Bin/location management
- Put-away rules and strategies
- Pick/pack/ship workflows
- Wave planning and release
- Cycle counting
- Cross-docking
- Mobile device support
- Dock scheduling

**Hooks:** `createPutaway`, `createPickTask`, `getLocationInventory`, `releaseWave`

**Events:** `putaway:completed`, `pick:completed`, `wave:released`, `shipment:confirmed`

---

### Shipping
**Priority:** P3 | **Dependencies:** Orders, Inventory

Shipping carrier integration and label generation.

**Features:**
- Carrier integrations (UPS, FedEx, DHL, etc.)
- Rate shopping
- Label generation
- Tracking updates
- Packing slip generation
- Batch shipping

**Hooks:** `getRates`, `createShipment`, `getTracking`

**Events:** `shipment:created`, `shipment:delivered`

---

### Returns / RMA
**Priority:** P2 | **Dependencies:** Orders, Inventory

Return merchandise authorization and reverse logistics management.

**Features:**
- RMA request creation
- Return reason tracking
- Inspection and disposition
- Refund/exchange/credit processing
- Restocking workflows
- Return shipping labels
- Warranty validation

**Hooks:** `createRMA`, `getRMAById`, `processReturn`, `issueRefund`

**Events:** `rma:created`, `rma:received`, `rma:processed`, `refund:issued`

---

### Demand Planning
**Priority:** P3 | **Dependencies:** Catalog, Orders

Sales forecasting and demand prediction for inventory optimization.

**Features:**
- Statistical forecasting models
- Seasonality and trend analysis
- Collaborative forecasting
- Forecast accuracy tracking
- Promotion impact modeling
- S&OP support

**Hooks:** `generateForecast`, `getForecastById`, `adjustForecast`, `getForecastAccuracy`

**Events:** `forecast:generated`, `forecast:adjusted`

---

## Manufacturing

Applications for production planning, execution, and quality control.

### Manufacturing
**Priority:** P2 | **Dependencies:** Catalog, Inventory, BOM

Production planning, work order management, and shop floor control.

**Features:**
- Work order creation and management
- Production scheduling
- Routing and operations
- Shop floor control
- Labor and machine time tracking
- WIP tracking
- Production reporting
- Capacity planning

**Hooks:** `createWorkOrder`, `getWorkOrderById`, `updateWorkOrderStatus`, `reportProduction`

**Events:** `workorder:created`, `workorder:started`, `workorder:completed`

---

### Quality Management
**Priority:** P3 | **Dependencies:** Manufacturing, Inventory

Quality control, inspections, and compliance for manufacturing operations.

**Features:**
- Inspection plans and checklists
- Quality control holds
- Non-conformance reporting (NCR)
- Corrective/preventive actions (CAPA)
- Statistical process control (SPC)
- Certificate of analysis (COA)
- Supplier quality management

**Hooks:** `createInspection`, `recordInspectionResult`, `createNCR`, `placeQCHold`

**Events:** `inspection:passed`, `inspection:failed`, `ncr:created`, `hold:placed`

---

### MRP (Material Requirements Planning)
**Priority:** P3 | **Dependencies:** BOM, Inventory, Manufacturing

Demand-driven planning for procurement and production scheduling.

**Features:**
- Demand forecasting integration
- Net requirements calculation
- Planned order generation
- Pegging and where-used
- Time-phased planning
- Safety stock planning
- Exception messages

**Hooks:** `runMRP`, `getPlannedOrders`, `getPegging`, `firmPlannedOrder`

**Events:** `mrp:completed`, `exception:generated`, `order:suggested`

---

## Finance

Applications for accounting, financial management, and compliance.

### General Ledger
**Priority:** P0 | **Dependencies:** None

Core financial accounting system. Foundation for all financial reporting and compliance.

**Features:**
- Chart of accounts management
- Journal entries (manual and automated)
- Multi-currency support
- Period management and closing
- Financial statements (P&L, Balance Sheet, Cash Flow)
- Trial balance and reconciliation
- Audit trail
- Intercompany transactions

**Hooks:** `createJournalEntry`, `getAccountBalance`, `getTrialBalance`, `closePeriod`

**Events:** `journal:posted`, `period:closed`, `account:reconciled`

---

### Accounts Payable
**Priority:** P1 | **Dependencies:** General Ledger, Purchasing

Vendor bill management, payment processing, and cash disbursement.

**Features:**
- Vendor bill entry and matching (3-way match)
- Payment scheduling and runs
- Check/ACH/wire payment support
- Early payment discounts
- Aging reports
- 1099 tracking
- Approval workflows

**Hooks:** `createBill`, `getBillById`, `schedulePayment`, `processPaymentRun`, `getAPAging`

**Events:** `bill:received`, `bill:approved`, `payment:scheduled`, `payment:processed`

---

### Accounts Receivable
**Priority:** P1 | **Dependencies:** General Ledger, Invoicing

Customer payment tracking, collections, and cash application.

**Features:**
- Payment application to invoices
- Aging reports and analysis
- Collection workflows and dunning
- Credit management and limits
- Cash receipt entry
- Write-offs and bad debt
- Customer statements

**Hooks:** `applyPayment`, `getARAging`, `getCustomerBalance`, `createDunningNotice`

**Events:** `payment:applied`, `invoice:pastdue`, `dunning:sent`, `writeoff:created`

---

### Fixed Assets
**Priority:** P2 | **Dependencies:** General Ledger

Track and manage company assets, depreciation, and disposals.

**Features:**
- Asset register and tracking
- Multiple depreciation methods
- Depreciation schedules
- Asset transfers
- Disposal and retirement
- Asset revaluation
- Maintenance history tracking

**Hooks:** `createAsset`, `getAssetById`, `calculateDepreciation`, `transferAsset`, `disposeAsset`

**Events:** `asset:acquired`, `asset:transferred`, `asset:disposed`, `depreciation:posted`

---

### Budgeting & Forecasting
**Priority:** P2 | **Dependencies:** General Ledger

Financial planning, budget management, and variance analysis.

**Features:**
- Budget creation by department/project/account
- Multiple budget versions and scenarios
- Rolling forecasts
- Variance analysis (budget vs. actual)
- What-if modeling
- Approval workflows

**Hooks:** `createBudget`, `getBudgetVsActual`, `getForecast`, `approveBudget`

**Events:** `budget:submitted`, `budget:approved`, `variance:alert`

---

### Tax Management
**Priority:** P2 | **Dependencies:** General Ledger, Invoicing

Tax calculation, compliance, and reporting across jurisdictions.

**Features:**
- Multi-jurisdiction tax rules
- Sales tax / VAT calculation
- Tax exemption management
- Tax reporting and filing preparation
- Withholding tax handling
- Integration with tax services (Avalara, etc.)

**Hooks:** `calculateTax`, `getTaxReport`, `validateTaxExemption`, `getTaxLiability`

**Events:** `tax:calculated`, `filing:due`, `exemption:expired`

---

### Expenses
**Priority:** P3 | **Dependencies:** General Ledger, Documents

Expense tracking and reimbursement.

**Features:**
- Expense entry
- Receipt capture
- Category management
- Approval workflows
- Reimbursement tracking
- Integration with accounting

**Hooks:** `submitExpense`, `approveExpense`, `getExpenseReport`

---

### Multi-Entity
**Priority:** P3 | **Dependencies:** General Ledger

Multi-company management, intercompany transactions, and consolidation.

**Features:**
- Multiple legal entities
- Intercompany transactions
- Automatic elimination entries
- Consolidated financial statements
- Shared master data options
- Entity-specific configurations
- Transfer pricing

**Hooks:** `createIntercompanyTransaction`, `runConsolidation`, `getConsolidatedFinancials`

**Events:** `intercompany:created`, `consolidation:completed`

---

## Customer Engagement

Applications for customer service, projects, and engagement.

### Support / Helpdesk
**Priority:** P3 | **Dependencies:** CRM

Customer support ticket management.

**Features:**
- Ticket creation and tracking
- Email-to-ticket
- Ticket assignment and routing
- SLA management
- Knowledge base
- Canned responses
- Customer satisfaction surveys

**Hooks:** `createTicket`, `getTicketById`, `assignTicket`

**Events:** `ticket:created`, `ticket:resolved`, `ticket:escalated`

---

### Projects
**Priority:** P3 | **Dependencies:** CRM

Project management for service-based businesses.

**Features:**
- Project creation and tracking
- Task management
- Time tracking
- Milestones and deadlines
- Team assignment
- Project templates
- Client portal view

**Hooks:** `createProject`, `logTime`, `getProjectStatus`

---

### Appointments
**Priority:** P3 | **Dependencies:** CRM

Scheduling and calendar management.

**Features:**
- Calendar view
- Appointment booking
- Resource scheduling
- Reminders and notifications
- Recurring appointments
- Online booking widget
- Calendar sync (Google, Outlook)

**Hooks:** `createAppointment`, `getAvailability`, `cancelAppointment`

**Events:** `appointment:created`, `appointment:cancelled`, `appointment:reminder`

---

### Email Marketing
**Priority:** P3 | **Dependencies:** CRM

Email campaign management and automation.

**Features:**
- Email template builder
- Campaign creation
- Contact list segmentation
- A/B testing
- Analytics (opens, clicks)
- Automation workflows
- Unsubscribe management

**Hooks:** `sendCampaign`, `addToList`, `getCampaignStats`

---

### Loyalty & Rewards
**Priority:** P3 | **Dependencies:** CRM, Orders

Customer loyalty program management.

**Features:**
- Points system
- Reward tiers
- Redemption rules
- Referral tracking
- Birthday rewards
- Program analytics

**Hooks:** `getPointsBalance`, `redeemPoints`, `awardPoints`

---

### Field Service
**Priority:** P2 | **Dependencies:** CRM, Inventory

Mobile workforce management for on-site service delivery.

**Features:**
- Service request management
- Technician dispatching and scheduling
- Route optimization
- Mobile app for field technicians
- Parts inventory on trucks
- Time and expense capture
- Customer signature capture
- SLA tracking

**Hooks:** `createServiceCall`, `dispatchTechnician`, `getSchedule`, `completeServiceCall`

**Events:** `service:scheduled`, `technician:dispatched`, `service:completed`

---

### Commissions
**Priority:** P3 | **Dependencies:** Orders, CRM

Sales commission calculation and payout management.

**Features:**
- Commission plan management
- Multiple commission structures (flat, tiered, percentage)
- Split commissions
- Quota tracking
- Commission statements
- Payout processing

**Hooks:** `calculateCommission`, `getCommissionStatement`, `processPayout`, `getQuotaAttainment`

**Events:** `commission:calculated`, `payout:processed`, `quota:achieved`

---

## Human Resources

Applications for workforce management.

### HRIS (Human Resources Information System)
**Priority:** P3 | **Dependencies:** Documents

Comprehensive human resources management.

**Features:**
- Employee directory and profiles
- Organization chart
- Time and attendance tracking
- Leave/PTO management
- Payroll processing
- Benefits administration
- Performance reviews
- Onboarding/offboarding workflows
- Training and certifications tracking

**Hooks:** `getEmployeeById`, `submitLeaveRequest`, `clockIn`, `clockOut`, `getPayrollSummary`

**Events:** `employee:hired`, `employee:terminated`, `leave:approved`, `payroll:processed`

---

### Contracts
**Priority:** P3 | **Dependencies:** CRM, Documents

Contract and agreement management.

**Features:**
- Contract templates
- E-signature integration
- Renewal tracking
- Contract versioning
- Expiration alerts
- Approval workflows

**Hooks:** `createContract`, `getContractStatus`, `sendForSignature`

---

## Assets & Operations

Applications for managing physical assets and operational equipment.

### Fleet Management
**Priority:** P3 | **Dependencies:** Fixed Assets

Vehicle tracking, maintenance scheduling, and driver management.

**Features:**
- Vehicle registry and tracking
- GPS/telematics integration
- Fuel management
- Maintenance scheduling
- Driver assignment and licensing
- Trip logging
- Compliance (DOT, HOS)

**Hooks:** `getVehicleById`, `assignDriver`, `logTrip`, `scheduleMaintenance`

**Events:** `maintenance:due`, `license:expiring`, `trip:completed`

---

### Maintenance / CMMS
**Priority:** P3 | **Dependencies:** Fixed Assets, Inventory

Computerized maintenance management for equipment and facilities.

**Features:**
- Asset/equipment registry
- Preventive maintenance schedules
- Work order management
- Spare parts inventory
- Maintenance history
- Downtime tracking
- Technician scheduling
- MTBF/MTTR metrics

**Hooks:** `createWorkOrder`, `getMaintenanceSchedule`, `logDowntime`, `completeWorkOrder`

**Events:** `maintenance:due`, `workorder:created`, `workorder:completed`, `downtime:logged`

---

### Rental Management
**Priority:** P3 | **Dependencies:** Catalog, Inventory, Invoicing

Equipment and asset rental operations management.

**Features:**
- Rental item catalog
- Availability calendar
- Reservation management
- Rental contracts
- Pick-up/delivery scheduling
- Usage metering
- Damage assessment
- Rental pricing (daily, weekly, monthly)

**Hooks:** `createRental`, `checkAvailability`, `extendRental`, `returnRental`

**Events:** `rental:created`, `rental:returned`, `rental:overdue`, `damage:assessed`

---

## Platform

Cross-cutting applications that enhance the entire platform.

### Documents
**Priority:** P0 | **Dependencies:** None

Document management and file storage for the platform.

**Features:**
- File upload and organization
- Folder structure
- Document tagging
- Version history
- Sharing and permissions
- Preview generation
- Integration with other apps

**Hooks:** `uploadDocument`, `getDocumentById`, `attachToEntity`

---

### Workflow Engine
**Priority:** P2 | **Dependencies:** None

Business process automation and approval management across all apps.

**Features:**
- Visual workflow designer
- Approval chains and routing
- Conditional branching
- Parallel and sequential tasks
- Escalation rules
- SLA monitoring
- Email/notification triggers
- Scheduled workflows
- Cross-app integration

**Hooks:** `createWorkflow`, `triggerWorkflow`, `getWorkflowStatus`, `approveTask`

**Events:** `workflow:started`, `workflow:completed`, `task:assigned`, `sla:breached`

---

### Audit & Compliance
**Priority:** P2 | **Dependencies:** None

Audit trail management, compliance tracking, and data governance.

**Features:**
- Comprehensive audit logging
- Data change tracking
- Access logging
- Compliance frameworks (SOX, GDPR, etc.)
- Retention policies
- Data export for auditors
- Segregation of duties enforcement

**Hooks:** `getAuditLog`, `getChangeHistory`, `exportAuditData`, `checkCompliance`

**Events:** `policy:violated`, `access:suspicious`, `retention:due`

---

### Reporting & Analytics
**Priority:** P2 | **Dependencies:** All apps (read-only)

Business intelligence dashboards and report generation.

**Features:**
- Sales reports
- Inventory reports
- Customer analytics
- Product performance
- Financial summaries
- Custom report builder
- Scheduled report delivery
- Export to PDF/Excel

**Hooks:** `generateReport`, `getMetrics`

---

### Payments
**Priority:** P2 | **Dependencies:** Invoicing, Orders

Payment processing integration and reconciliation.

**Features:**
- Payment gateway integrations (Stripe, PayPal, etc.)
- Payment link generation
- Automatic reconciliation
- Refund processing
- Payment method management
- PCI compliance handling

**Hooks:** `createPaymentLink`, `processRefund`, `getPaymentStatus`

**Events:** `payment:received`, `payment:failed`, `payment:refunded`

---

### EDI & Integrations
**Priority:** P3 | **Dependencies:** Orders, Invoicing, Inventory

Electronic data interchange and trading partner connectivity.

**Features:**
- EDI document support (850, 855, 856, 810, etc.)
- Trading partner management
- Document mapping and transformation
- AS2/SFTP connectivity
- API gateway for partners
- Error handling and retry

**Hooks:** `sendEDIDocument`, `receiveEDIDocument`, `getTradingPartner`

**Events:** `edi:sent`, `edi:received`, `edi:error`, `partner:connected`

---

## Implementation Phases

### Phase 1: Foundation
- Catalog (P0)
- CRM (P0)
- General Ledger (P0)
- Documents (P0)

### Phase 2: Commerce
- Invoicing (P1)
- Orders (P1)
- Inventory (P1)

### Phase 3: Finance
- Accounts Payable (P1)
- Accounts Receivable (P1)
- Purchasing (P1)

### Phase 4: Sales Expansion
- Quotes & CPQ (P2)
- B2B E-Commerce (P2)
- Payments (P2)

### Phase 5: Supply Chain
- Warehouse Management (P2)
- Returns / RMA (P2)

### Phase 6: Manufacturing
- Bill of Materials (P2)
- Manufacturing (P2)

### Phase 7: Financial Management
- Fixed Assets (P2)
- Budgeting & Forecasting (P2)
- Tax Management (P2)
- Subscription Management (P2)

### Phase 8: Platform Enhancement
- Workflow Engine (P2)
- Audit & Compliance (P2)
- Reporting & Analytics (P2)
- Field Service (P2)

### Phase 9: Customer Engagement
- Support / Helpdesk (P3)
- Projects (P3)
- Appointments (P3)
- Email Marketing (P3)
- Loyalty & Rewards (P3)
- Commissions (P3)

### Phase 10: Operations
- Shipping (P3)
- Contracts (P3)
- Expenses (P3)
- HRIS (P3)

### Phase 11: Advanced Manufacturing
- Quality Management (P3)
- MRP (P3)
- Demand Planning (P3)

### Phase 12: Asset Management
- Fleet Management (P3)
- Maintenance / CMMS (P3)
- Rental Management (P3)

### Phase 13: Enterprise
- Multi-Entity (P3)
- EDI & Integrations (P3)

---

## Dependency Graph

```
═══════════════════════════════════════════════════════════════════════════════
                           FOUNDATION (P0)
═══════════════════════════════════════════════════════════════════════════════

┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   Catalog   │  │     CRM     │  │   General   │  │  Documents  │
│     P0      │  │     P0      │  │   Ledger    │  │     P0      │
└──────┬──────┘  └──────┬──────┘  │     P0      │  └──────┬──────┘
       │                │         └──────┬──────┘         │
       │                │                │                │
       ▼                ▼                ▼                ▼
   Products          Customers       Accounting        Files


═══════════════════════════════════════════════════════════════════════════════
                           SALES FLOW
═══════════════════════════════════════════════════════════════════════════════

┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│   CRM   │────▶│ Quotes  │────▶│ Orders  │────▶│Invoicing│
│   P0    │     │   P2    │     │   P1    │     │   P1    │
└─────────┘     └─────────┘     └─────────┘     └────┬────┘
                                     │               │
                                     ▼               ▼
                              ┌─────────┐     ┌─────────┐
                              │B2B E-Com│     │Payments │
                              │   P2    │     │   P2    │
                              └─────────┘     └─────────┘


═══════════════════════════════════════════════════════════════════════════════
                           SUPPLY CHAIN FLOW
═══════════════════════════════════════════════════════════════════════════════

┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│ Catalog │────▶│Inventory│────▶│   WMS   │────▶│Shipping │
│   P0    │     │   P1    │     │   P2    │     │   P3    │
└─────────┘     └────┬────┘     └─────────┘     └─────────┘
                     │
         ┌───────────┼───────────┐
         ▼           ▼           ▼
   ┌──────────┐ ┌─────────┐ ┌─────────┐
   │Purchasing│ │Returns  │ │ Demand  │
   │   P1     │ │   P2    │ │Planning │
   └──────────┘ └─────────┘ │   P3    │
                            └─────────┘


═══════════════════════════════════════════════════════════════════════════════
                           MANUFACTURING FLOW
═══════════════════════════════════════════════════════════════════════════════

┌─────────┐     ┌─────────┐     ┌─────────┐
│ Catalog │────▶│   BOM   │────▶│Manufact.│
│   P0    │     │   P2    │     │   P2    │
└─────────┘     └─────────┘     └────┬────┘
                                     │
                          ┌──────────┼──────────┐
                          ▼          ▼          ▼
                    ┌─────────┐ ┌─────────┐ ┌─────────┐
                    │ Quality │ │   MRP   │ │Inventory│
                    │   P3    │ │   P3    │ │   P1    │
                    └─────────┘ └─────────┘ └─────────┘


═══════════════════════════════════════════════════════════════════════════════
                           FINANCE FLOW
═══════════════════════════════════════════════════════════════════════════════

                         ┌─────────────┐
                         │   General   │
                         │   Ledger    │
                         │     P0      │
                         └──────┬──────┘
                                │
    ┌───────────┬───────────────┼───────────────┬───────────┐
    ▼           ▼               ▼               ▼           ▼
┌───────┐  ┌─────────┐    ┌─────────┐    ┌─────────┐  ┌─────────┐
│  AP   │  │   AR    │    │  Fixed  │    │Budgeting│  │  Multi  │
│  P1   │  │   P1    │    │ Assets  │    │   P2    │  │ Entity  │
└───────┘  └─────────┘    │   P2    │    └─────────┘  │   P3    │
                          └────┬────┘                 └─────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
              ┌─────────┐ ┌─────────┐ ┌─────────┐
              │  Fleet  │ │  CMMS   │ │ Rental  │
              │   P3    │ │   P3    │ │   P3    │
              └─────────┘ └─────────┘ └─────────┘
```

---

## Architecture Notes

### Core Principles
- All apps implement `eldrin-app.manifest.json` specification
- Apps communicate via hooks (direct calls) and events (pub/sub)
- Each app maintains its own D1 database
- Shared assets stored in R2
- Apps must use Eldrin design tokens for consistent UI

### Key Dependencies
- **Catalog** - Product master for commerce, supply chain, and manufacturing
- **CRM** - Customer master for sales and service apps
- **General Ledger** - Financial backbone for all finance apps
- **Inventory** - Bridges commerce, supply chain, and manufacturing
- **Documents** - File storage for all apps

### Integration Patterns
- Financial transactions auto-post to General Ledger
- Order fulfillment triggers inventory, shipping, and invoicing
- Manufacturing consumes BOM and Inventory, produces finished goods
- All apps publish audit events for compliance

### Scalability Path
1. **Startup**: P0 apps for basic operations
2. **SMB**: P0 + P1 apps for commerce and finance
3. **Mid-Market**: Add P2 apps for manufacturing and advanced features
4. **Enterprise**: P3 apps for multi-entity, EDI, and advanced planning
