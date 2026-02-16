# CRM APPLICATION — COMPREHENSIVE REQUIREMENTS SPECIFICATION

**Phased Implementation Roadmap — From MVP to Enterprise-Grade Platform**

|                    |                         |
| ------------------ | ----------------------- |
| **Version**        | 1.0                     |
| **Date**           | February 2026           |
| **Status**         | Draft                   |
| **Classification** | Internal / Confidential |

---

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. Phased Roadmap Overview](#2-phased-roadmap-overview)
- [3. Requirement Priority Definitions](#3-requirement-priority-definitions)
- [4. Detailed Requirements by Phase](#4-detailed-requirements-by-phase)
  - [Phase 1: Core CRM Foundation (MVP)](#phase-1-core-crm-foundation-mvp)
  - [Phase 2: Sales Automation & Productivity](#phase-2-sales-automation--productivity)
  - [Phase 3: Marketing & Communication](#phase-3-marketing--communication)
  - [Phase 4: Customer Service & Support](#phase-4-customer-service--support)
  - [Phase 5: Advanced Analytics & Business Intelligence](#phase-5-advanced-analytics--business-intelligence)
  - [Phase 6: Integration Platform & Extensibility](#phase-6-integration-platform--extensibility)
  - [Phase 7: AI & Intelligent Automation](#phase-7-ai--intelligent-automation)
  - [Phase 8: Enterprise Features & Scale](#phase-8-enterprise-features--scale)
- [5. Non-Functional Requirements](#5-non-functional-requirements)
- [6. Competitive Feature Matrix](#6-competitive-feature-matrix)
- [7. Requirements Summary](#7-requirements-summary)
- [8. Glossary](#8-glossary)

---

## 1. Executive Summary

This document defines the comprehensive functional requirements for a Customer Relationship Management (CRM) application designed to serve as the organisation's central platform for managing customer interactions, sales processes, marketing campaigns, and customer support operations.

The requirements have been informed by an analysis of features offered by the leading CRM platforms in the market, including Salesforce, HubSpot, Microsoft Dynamics 365, Zoho CRM, and Pipedrive. The goal is to build a CRM that incorporates best-in-class capabilities from these platforms while being architected for phased delivery.

The implementation is structured into eight phases, beginning with a Minimum Viable Product (MVP) in Phase 1 that delivers the core CRM functionality needed for a fast go-live, and progressively adding sales automation, marketing, customer service, analytics, integrations, AI, and enterprise features in subsequent phases.

**Authentication, user management, and role-based access control are already implemented and are referenced (not re-specified) throughout this document.**

---

## 2. Phased Roadmap Overview

The following table summarises the eight implementation phases, their target timelines, and the functional areas addressed in each.

| Phase       | Name                            | Timeline      | Key Modules                                                                        |
| ----------- | ------------------------------- | ------------- | ---------------------------------------------------------------------------------- |
| **1 (MVP)** | Core CRM Foundation             | Months 1–4    | Contacts, Companies, Leads, Deals, Activities, Basic Reports, Email, Import/Export |
| **2**       | Sales Automation & Productivity | Months 5–7    | Workflows, Sequences, Products, Quotes, Forecasting, Customisation, Documents      |
| **3**       | Marketing & Communication       | Months 8–11   | Campaigns, Email Marketing, Landing Pages, Chat, SMS, Social Media                 |
| **4**       | Customer Service & Support      | Months 12–15  | Ticketing, SLA, Knowledge Base, Customer Portal, Surveys                           |
| **5**       | Advanced Analytics & BI         | Months 16–18  | Custom Reports, Dashboards, Revenue Analytics, Productivity Analytics              |
| **6**       | Integration Platform            | Months 19–22  | REST API, Webhooks, Google/Microsoft/Slack, Mobile App, Data Migration             |
| **7**       | AI & Intelligent Automation     | Months 23–26  | AI Scoring, Sales Copilot, Conversation Intelligence, Predictive Analytics         |
| **8**       | Enterprise Features & Scale     | Months 27–32+ | Multi-currency, Territories, Approvals, Compliance, PRM, Field Service, Commerce   |

---

## 3. Requirement Priority Definitions

Requirements are prioritised using the MoSCoW method within each phase:

| Priority   | Definition                                                                                                       |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| **Must**   | Essential for the phase to be considered complete. The phase cannot go live without these.                       |
| **Should** | Important and expected. Should be included unless time or resource constraints force deferral to the next phase. |
| **Could**  | Desirable enhancement. Include if capacity allows; otherwise defer without impacting the phase's core value.     |

---

## 4. Detailed Requirements by Phase

---

### Phase 1: Core CRM Foundation (MVP)

**Target Timeline:** Months 1–4

*Deliver a functional CRM that replaces spreadsheets and provides a single source of truth for contacts, companies, deals, and activities. This phase enables the sales team to manage their day-to-day pipeline and basic reporting from day one.*

---

#### 1.1 Contact & Company Management

*Central repository for all people and organisations the business interacts with. Inspired by Salesforce Accounts/Contacts, HubSpot Contact Management, and Zoho CRM contact modules.*

| Req ID     | Priority   | Requirement                                                                                                                                                                         |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-1.1.01 | **Must**   | Create, read, update, and delete (CRUD) contact records with fields: first name, last name, email(s), phone(s), job title, department, social profiles, address, and custom fields. |
| REQ-1.1.02 | **Must**   | Create, read, update, and delete company/organisation records with fields: name, domain, industry, size, revenue range, address, phone, website, and custom fields.                 |
| REQ-1.1.03 | **Must**   | Associate multiple contacts to a single company with role labels (e.g. Decision Maker, Influencer, End User).                                                                       |
| REQ-1.1.04 | **Must**   | Support parent-child company hierarchies for enterprise account structures.                                                                                                         |
| REQ-1.1.05 | **Must**   | Automatic duplicate detection on create/import based on email, phone, and company domain with merge capability.                                                                     |
| REQ-1.1.06 | **Must**   | Activity timeline on each record showing all related emails, calls, notes, meetings, and deal changes in reverse chronological order.                                               |
| REQ-1.1.07 | **Should** | Contact and company enrichment from publicly available data (domain lookup, social profiles).                                                                                       |
| REQ-1.1.08 | **Should** | Gravatar/profile photo auto-fetch and manual upload capability.                                                                                                                     |
| REQ-1.1.09 | **Must**   | Tag and segment contacts using user-defined tags, lists, and smart filters.                                                                                                         |
| REQ-1.1.10 | **Must**   | Full-text search across all contact and company fields with advanced filter builder (AND/OR conditions).                                                                            |
| REQ-1.1.11 | **Should** | Map view for contacts/companies with geocoded addresses.                                                                                                                            |
| REQ-1.1.12 | **Must**   | Configurable list views with column selection, sorting, and saved views per user/team.                                                                                              |

---

#### 1.2 Lead Management

*Capture, qualify, and convert leads into contacts and deals. Modelled after Salesforce Lead Management, HubSpot lead tools, and Pipedrive lead inbox.*

| Req ID     | Priority   | Requirement                                                                                                                      |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| REQ-1.2.01 | **Must**   | Separate Lead entity with status lifecycle: New, Contacted, Qualified, Unqualified, Converted, and custom statuses.              |
| REQ-1.2.02 | **Must**   | Lead capture via manual entry, CSV import, and web form submissions (API endpoint for web forms).                                |
| REQ-1.2.03 | **Must**   | Lead source tracking (Web, Referral, Event, Cold Call, Advertisement, Partner, etc.) with custom sources.                        |
| REQ-1.2.04 | **Must**   | Lead assignment rules: round-robin, territory-based, manual, and load-balanced distribution.                                     |
| REQ-1.2.05 | **Must**   | Lead conversion workflow that creates a Contact, Company (if new), and optionally a Deal in one action, preserving full history. |
| REQ-1.2.06 | **Should** | Basic lead scoring based on configurable rules (e.g. +10 for email opened, +20 for demo requested).                              |
| REQ-1.2.07 | **Should** | Lead aging alerts: notify owner when lead has not been contacted within a configurable SLA.                                      |
| REQ-1.2.08 | **Could**  | Web-to-lead form builder with embeddable HTML/JS snippets for external websites.                                                 |

---

#### 1.3 Deal / Opportunity Management

*Track revenue opportunities through customisable sales pipelines. Inspired by Pipedrive visual pipelines, Salesforce Opportunity management, and HubSpot deal tracking.*

| Req ID     | Priority   | Requirement                                                                                                                                                                       |
| ---------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-1.3.01 | **Must**   | Create, read, update, and delete deal records with fields: name, value, currency, expected close date, stage, probability, owner, associated contacts/company, and custom fields. |
| REQ-1.3.02 | **Must**   | Multiple configurable sales pipelines (e.g. New Business, Upsell, Partner) each with customisable stages, stage probabilities, and win/loss reasons.                              |
| REQ-1.3.03 | **Must**   | Kanban board view with drag-and-drop stage progression (Pipedrive-style).                                                                                                         |
| REQ-1.3.04 | **Must**   | List view and table view with sortable columns, inline editing, and saved filters.                                                                                                |
| REQ-1.3.05 | **Must**   | Deal activity requirements per stage (e.g. discovery call required before moving to Proposal stage).                                                                              |
| REQ-1.3.06 | **Must**   | Won/Lost/Abandoned close-out flow with required reason codes and optional notes.                                                                                                  |
| REQ-1.3.07 | **Should** | Weighted pipeline value calculation: sum of (deal value × stage probability).                                                                                                     |
| REQ-1.3.08 | **Should** | Deal rotting indicators: visual cue when a deal has been in the same stage beyond a configurable threshold.                                                                       |
| REQ-1.3.09 | **Could**  | Deal cloning for recurring or similar opportunities.                                                                                                                              |
| REQ-1.3.10 | **Must**   | Associate multiple contacts to a deal with contact roles (Champion, Budget Holder, Technical Evaluator, etc.).                                                                    |

---

#### 1.4 Activity & Task Management

*Log and schedule all sales activities. Based on Salesforce Activity Management, HubSpot task management, and Zoho CRM activities.*

| Req ID     | Priority   | Requirement                                                                                                                                                  |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| REQ-1.4.01 | **Must**   | Activity types: Call, Email, Meeting, Task, Note, Lunch, and user-defined custom types.                                                                      |
| REQ-1.4.02 | **Must**   | Create tasks with title, description, due date/time, priority (Low/Medium/High/Urgent), status, assignee, and related record (contact, company, deal, lead). |
| REQ-1.4.03 | **Must**   | Calendar view (day/week/month) showing all scheduled activities with colour coding by type.                                                                  |
| REQ-1.4.04 | **Must**   | Overdue task highlighting and daily digest notification (email and in-app).                                                                                  |
| REQ-1.4.05 | **Must**   | Quick-log call/meeting outcome with duration, notes, and next steps.                                                                                         |
| REQ-1.4.06 | **Should** | Recurring task creation (daily, weekly, monthly, custom).                                                                                                    |
| REQ-1.4.07 | **Should** | Activity reminders via in-app notification and email, configurable per activity.                                                                             |
| REQ-1.4.08 | **Could**  | Sync with external calendars (Google Calendar, Outlook) — initial read-only display; full two-way sync in Phase 6.                                           |

---

#### 1.5 Basic Reporting & Dashboards

*Out-of-the-box reports and dashboards for sales visibility. Inspired by Salesforce Reports & Dashboards and HubSpot reporting.*

| Req ID     | Priority   | Requirement                                                                                                                                  |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-1.5.01 | **Must**   | Pre-built dashboard with KPIs: open deals, pipeline value, deals won/lost this period, conversion rate, activities completed, and new leads. |
| REQ-1.5.02 | **Must**   | Pipeline funnel report showing deal count and value per stage.                                                                               |
| REQ-1.5.03 | **Must**   | Sales activity report: activities by type, by user, by date range.                                                                           |
| REQ-1.5.04 | **Must**   | Lead source effectiveness report: leads by source, conversion rate per source.                                                               |
| REQ-1.5.05 | **Must**   | Date range filtering (today, this week, this month, this quarter, this year, custom range) on all reports.                                   |
| REQ-1.5.06 | **Should** | Export reports to CSV and PDF.                                                                                                               |
| REQ-1.5.07 | **Should** | Dashboard widgets: bar chart, line chart, pie chart, number card, leaderboard, table.                                                        |
| REQ-1.5.08 | **Could**  | Personalised home dashboard per user with drag-and-drop widget arrangement.                                                                  |

---

#### 1.6 Email Integration (Basic)

*Connect the CRM to email for logging and sending. Based on HubSpot email tracking and Salesforce email integration.*

| Req ID     | Priority   | Requirement                                                                                                    |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------- |
| REQ-1.6.01 | **Must**   | Send email from within contact/deal/lead record using the CRM's email composer.                                |
| REQ-1.6.02 | **Must**   | BCC-to-CRM email address: automatically log emails sent from any mail client by BCCing a unique CRM address.   |
| REQ-1.6.03 | **Must**   | Email templates: create, edit, and reuse templates with merge fields (contact name, company, deal name, etc.). |
| REQ-1.6.04 | **Should** | Email open and click tracking with notification to the deal/contact owner.                                     |
| REQ-1.6.05 | **Should** | Shared team email templates library with permission controls.                                                  |
| REQ-1.6.06 | **Could**  | Email scheduling: compose now, send at a specified future date/time.                                           |

---

#### 1.7 Data Import / Export

*Migrate data into the CRM and extract data for external use.*

| Req ID     | Priority   | Requirement                                                                                           |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------- |
| REQ-1.7.01 | **Must**   | CSV import for contacts, companies, leads, and deals with field mapping UI and preview before commit. |
| REQ-1.7.02 | **Must**   | Duplicate handling during import: skip, overwrite, or create duplicate with flag.                     |
| REQ-1.7.03 | **Must**   | CSV export for all major entities with field selection.                                               |
| REQ-1.7.04 | **Should** | Import history log with rollback capability for recent imports.                                       |
| REQ-1.7.05 | **Could**  | Excel (.xlsx) import/export support.                                                                  |

---

#### 1.8 Users, Roles & Permissions (Reference)

*Authentication and authorisation are already implemented. This section documents the expected capabilities that the CRM features will rely upon.*

| Req ID     | Priority   | Requirement                                                                                                                    |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------ |
| REQ-1.8.01 | **Must**   | Role-based access control (RBAC) with predefined roles: Admin, Sales Manager, Sales Rep, Marketing, Support, and custom roles. |
| REQ-1.8.02 | **Must**   | Entity-level permissions: create, read, update, delete per entity type per role.                                               |
| REQ-1.8.03 | **Must**   | Record-level ownership: users own records and visibility can be restricted to own records, team records, or all records.       |
| REQ-1.8.04 | **Must**   | Team/group management: organise users into teams with shared record visibility.                                                |
| REQ-1.8.05 | **Should** | Field-level security: hide or make read-only specific fields based on role.                                                    |
| REQ-1.8.06 | **Should** | Permission sets that can be layered on top of base roles for granular control.                                                 |

---

#### 1.9 System & UX Foundations

*Cross-cutting capabilities that support the entire application.*

| Req ID     | Priority   | Requirement                                                                                      |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------ |
| REQ-1.9.01 | **Must**   | Responsive web application optimised for desktop and tablet viewports.                           |
| REQ-1.9.02 | **Must**   | Global search bar with instant results across contacts, companies, leads, deals, and activities. |
| REQ-1.9.03 | **Must**   | In-app notification centre with unread badge count.                                              |
| REQ-1.9.04 | **Must**   | Audit log of record changes: who changed what field, old value, new value, timestamp.            |
| REQ-1.9.05 | **Must**   | Soft delete (recycle bin) with admin restore capability within 30 days.                          |
| REQ-1.9.06 | **Should** | Customisable navigation sidebar with pinnable modules.                                           |
| REQ-1.9.07 | **Should** | Dark mode / light mode theme toggle.                                                             |
| REQ-1.9.08 | **Could**  | Keyboard shortcuts for power users (e.g. "G then D" to go to Deals).                             |

---

### Phase 2: Sales Automation & Productivity

**Target Timeline:** Months 5–7

*Automate repetitive sales tasks, enable structured quoting, and provide advanced customisation to accelerate deal velocity. Features inspired by Salesforce Process Builder, HubSpot Sequences, Zoho workflow rules, and Pipedrive automation.*

---

#### 2.1 Workflow Automation Engine

*Rule-based automation to eliminate manual work. Inspired by Salesforce Flow, HubSpot Workflows, and Zoho Blueprint.*

| Req ID     | Priority   | Requirement                                                                                                                                  |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-2.1.01 | **Must**   | Visual workflow builder with trigger → condition → action paradigm.                                                                          |
| REQ-2.1.02 | **Must**   | Triggers: record created, record updated (specific field change), stage change, date-based (e.g. 3 days after creation), and manual trigger. |
| REQ-2.1.03 | **Must**   | Conditions: field value comparisons (equals, contains, greater than, is empty, etc.) with AND/OR logic.                                      |
| REQ-2.1.04 | **Must**   | Actions: send email (from template), create task, update field, send in-app notification, send webhook, assign owner, and add tag.           |
| REQ-2.1.05 | **Should** | Time-delay steps: wait X hours/days before executing next action.                                                                            |
| REQ-2.1.06 | **Should** | Workflow execution log with success/failure status per run for debugging.                                                                    |
| REQ-2.1.07 | **Could**  | Workflow templates library with pre-built common automations (e.g. "Follow up after demo").                                                  |

---

#### 2.2 Email Sequences & Cadences

*Multi-step automated email outreach. Based on HubSpot Sequences and Salesforce Sales Engagement.*

| Req ID     | Priority   | Requirement                                                                                                                                 |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-2.2.01 | **Must**   | Create multi-step email sequences with configurable delays between steps (e.g. Day 1: intro email, Day 3: follow-up, Day 7: breakup email). |
| REQ-2.2.02 | **Must**   | Automatic unenrollment when prospect replies, books a meeting, or deal stage changes.                                                       |
| REQ-2.2.03 | **Must**   | Merge field personalisation in sequence emails (first name, company, custom fields).                                                        |
| REQ-2.2.04 | **Should** | A/B testing of email subject lines and body content within sequences.                                                                       |
| REQ-2.2.05 | **Should** | Sequence performance analytics: open rate, reply rate, bounce rate, meetings booked per sequence.                                           |
| REQ-2.2.06 | **Could**  | Manual task steps within sequences (e.g. "Call contact" reminder between emails).                                                           |

---

#### 2.3 Product & Price Book Management

*Maintain a catalogue of products/services for quoting. Based on Salesforce Product & Price Book and Zoho Products module.*

| Req ID     | Priority   | Requirement                                                                                                                   |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------- |
| REQ-2.3.01 | **Must**   | Product catalogue with fields: name, SKU, description, category, unit price, currency, tax class, and active/inactive status. |
| REQ-2.3.02 | **Must**   | Multiple price books (e.g. Standard, Partner, Enterprise) with different pricing per product.                                 |
| REQ-2.3.03 | **Should** | Volume/tiered pricing: define price breaks based on quantity ranges.                                                          |
| REQ-2.3.04 | **Should** | Recurring pricing support: monthly, quarterly, annual billing periods.                                                        |
| REQ-2.3.05 | **Could**  | Product bundles: group products into bundles with bundle-level pricing.                                                       |

---

#### 2.4 Quote & Proposal Management

*Generate professional sales quotes linked to deals. Inspired by Salesforce CPQ, HubSpot Quotes, and Zoho Quotes.*

| Req ID     | Priority   | Requirement                                                                                                                      |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| REQ-2.4.01 | **Must**   | Create quotes linked to a deal with line items from the product catalogue, quantity, unit price, discount (% or fixed), and tax. |
| REQ-2.4.02 | **Must**   | Quote status lifecycle: Draft, Sent, Viewed, Accepted, Rejected, Expired.                                                        |
| REQ-2.4.03 | **Must**   | Generate PDF quote from a configurable template with company branding, terms and conditions, and signatory block.                |
| REQ-2.4.04 | **Should** | Quote approval workflow: require manager approval when discount exceeds a configurable threshold.                                |
| REQ-2.4.05 | **Should** | Electronic signature integration (prepare for Phase 6 third-party integration).                                                  |
| REQ-2.4.06 | **Should** | Quote versioning: maintain history of revisions with comparison view.                                                            |
| REQ-2.4.07 | **Could**  | Shareable quote link: send a web link instead of PDF, with online acceptance button.                                             |

---

#### 2.5 Sales Forecasting

*Predict future revenue based on pipeline data. Based on Salesforce Forecasting and HubSpot forecast tools.*

| Req ID     | Priority   | Requirement                                                                                                                         |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| REQ-2.5.01 | **Must**   | Forecast view by period (monthly/quarterly) showing pipeline value grouped by stage category: Commit, Best Case, Pipeline, Omitted. |
| REQ-2.5.02 | **Must**   | Forecast roll-up by team hierarchy: individual rep → manager → VP → organisation.                                                   |
| REQ-2.5.03 | **Should** | Manager override: allow managers to submit adjusted forecast numbers alongside system-calculated values.                            |
| REQ-2.5.04 | **Should** | Forecast vs. actual comparison over historical periods with trend line.                                                             |
| REQ-2.5.05 | **Could**  | Quota setting per user/team per period and quota attainment tracking.                                                               |

---

#### 2.6 Advanced Customisation

*Enable admins to tailor the CRM without code changes. Inspired by Salesforce Platform customisation and Zoho CRM customisation.*

| Req ID     | Priority   | Requirement                                                                                                                                                                                 |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-2.6.01 | **Must**   | Custom fields on all entities: text, number, decimal, date, datetime, dropdown (single/multi), checkbox, URL, email, phone, currency, formula, and lookup (relationship to another entity). |
| REQ-2.6.02 | **Must**   | Custom entities/objects: admin-definable entities with custom fields, list views, and record pages.                                                                                         |
| REQ-2.6.03 | **Should** | Page layout editor: configure which fields appear on create/edit forms per entity per role.                                                                                                 |
| REQ-2.6.04 | **Should** | Conditional field visibility: show/hide fields based on other field values.                                                                                                                 |
| REQ-2.6.05 | **Should** | Validation rules: enforce data quality rules on save (e.g. close date must be in the future, email format check).                                                                           |
| REQ-2.6.06 | **Could**  | Custom relationship types between entities (many-to-many with junction object).                                                                                                             |

---

#### 2.7 Document Management

*Centralise sales collateral and track document engagement.*

| Req ID     | Priority   | Requirement                                                                                                                |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------------- |
| REQ-2.7.01 | **Must**   | File attachment on any record (contacts, companies, deals, leads) with drag-and-drop upload.                               |
| REQ-2.7.02 | **Must**   | Central document library with folder structure, tagging, and search.                                                       |
| REQ-2.7.03 | **Should** | Document versioning: upload new versions while retaining history.                                                          |
| REQ-2.7.04 | **Could**  | Trackable document links: share a link and track when the recipient views the document and which pages they spent time on. |

---

#### 2.8 Bulk Operations

*Efficiently update records at scale.*

| Req ID     | Priority   | Requirement                                                                             |
| ---------- | ---------- | --------------------------------------------------------------------------------------- |
| REQ-2.8.01 | **Must**   | Bulk select records in list views (select all, select page, individual checkboxes).     |
| REQ-2.8.02 | **Must**   | Bulk update: change a field value across all selected records.                          |
| REQ-2.8.03 | **Must**   | Bulk delete with confirmation and recycle bin support.                                  |
| REQ-2.8.04 | **Should** | Bulk reassign: transfer ownership of selected records to another user.                  |
| REQ-2.8.05 | **Should** | Bulk email: send a template email to all selected contacts (with daily sending limits). |

---

### Phase 3: Marketing & Communication

**Target Timeline:** Months 8–11

*Extend the CRM into a marketing hub with campaign management, email marketing, landing pages, and multi-channel communication. Modelled after Salesforce Marketing Cloud, HubSpot Marketing Hub, and Zoho Marketing Automation.*

---

#### 3.1 Campaign Management

*Plan, execute, and measure marketing campaigns.*

| Req ID     | Priority   | Requirement                                                                                                                                                       |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-3.1.01 | **Must**   | Campaign entity with fields: name, type (Email, Event, Webinar, Advertisement, Social, Other), status, start/end date, budget, actual cost, and expected revenue. |
| REQ-3.1.02 | **Must**   | Associate leads, contacts, and deals to campaigns to track influence and attribution.                                                                             |
| REQ-3.1.03 | **Must**   | Campaign performance metrics: leads generated, contacts reached, deals influenced, revenue attributed, ROI.                                                       |
| REQ-3.1.04 | **Should** | Campaign hierarchy: parent campaigns with child sub-campaigns for complex initiatives.                                                                            |
| REQ-3.1.05 | **Should** | First-touch and last-touch attribution models; multi-touch attribution in Phase 5.                                                                                |

---

#### 3.2 Email Marketing

*Mass email campaigns with templates and analytics. Based on HubSpot Email, Salesforce Marketing Cloud Email Studio, and Zoho Campaigns.*

| Req ID     | Priority   | Requirement                                                                                                         |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------- |
| REQ-3.2.01 | **Must**   | Drag-and-drop email builder with responsive templates, image hosting, and merge fields.                             |
| REQ-3.2.02 | **Must**   | Contact list/segment-based email sends with opt-in/opt-out (unsubscribe) management.                                |
| REQ-3.2.03 | **Must**   | Email analytics per campaign: sent, delivered, opened, clicked, bounced, unsubscribed.                              |
| REQ-3.2.04 | **Must**   | GDPR/CAN-SPAM compliance: mandatory unsubscribe link, physical address, and consent tracking.                       |
| REQ-3.2.05 | **Should** | A/B testing: test subject line, sender name, or content variant with automatic winner selection.                    |
| REQ-3.2.06 | **Should** | Send time optimisation: schedule sends at optimal time per contact's timezone or engagement history.                |
| REQ-3.2.07 | **Should** | Drip campaign / marketing automation: trigger-based multi-step email flows (e.g. welcome series, nurture sequence). |
| REQ-3.2.08 | **Could**  | Dynamic content blocks: show different content sections based on contact attributes.                                |

---

#### 3.3 Landing Pages & Web Forms

*Capture leads from the web. Inspired by HubSpot Landing Pages and Pardot forms.*

| Req ID     | Priority   | Requirement                                                                                                       |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------- |
| REQ-3.3.01 | **Must**   | Drag-and-drop landing page builder with responsive templates and custom branding.                                 |
| REQ-3.3.02 | **Must**   | Embeddable web forms with configurable fields, validation, and CRM field mapping.                                 |
| REQ-3.3.03 | **Must**   | Form submission creates or updates a lead/contact in the CRM with source tracking.                                |
| REQ-3.3.04 | **Should** | Progressive profiling: ask for additional information on subsequent form fills instead of repeating known fields. |
| REQ-3.3.05 | **Should** | Landing page analytics: visits, form submissions, conversion rate.                                                |
| REQ-3.3.06 | **Could**  | Pop-up and slide-in form types with trigger rules (exit intent, time on page, scroll depth).                      |

---

#### 3.4 Live Chat & Chatbot

*Real-time visitor engagement. Based on HubSpot Live Chat, Salesforce Service Cloud Chat, and Zoho SalesIQ.*

| Req ID     | Priority   | Requirement                                                                                                 |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------- |
| REQ-3.4.01 | **Must**   | Embeddable live chat widget for websites with agent assignment and availability hours.                      |
| REQ-3.4.02 | **Must**   | Chat transcripts automatically logged on the contact's activity timeline.                                   |
| REQ-3.4.03 | **Should** | Chatbot builder with decision-tree logic: greeting, qualify, capture email, route to agent or book meeting. |
| REQ-3.4.04 | **Should** | Pre-chat form to capture visitor name and email before starting a conversation.                             |
| REQ-3.4.05 | **Could**  | Canned responses for agents to speed up chat handling.                                                      |

---

#### 3.5 SMS & Messaging

*Multi-channel outreach beyond email.*

| Req ID     | Priority   | Requirement                                                                         |
| ---------- | ---------- | ----------------------------------------------------------------------------------- |
| REQ-3.5.01 | **Should** | SMS sending from contact/lead records via integrated SMS gateway (e.g. Twilio).     |
| REQ-3.5.02 | **Should** | SMS templates with merge fields.                                                    |
| REQ-3.5.03 | **Could**  | WhatsApp Business API integration for messaging.                                    |
| REQ-3.5.04 | **Could**  | Unified inbox: view email, chat, and SMS conversations in one timeline per contact. |

---

#### 3.6 Social Media Integration

*Connect social channels to the CRM.*

| Req ID     | Priority   | Requirement                                                                                  |
| ---------- | ---------- | -------------------------------------------------------------------------------------------- |
| REQ-3.6.01 | **Should** | Social profile linking: associate LinkedIn, Twitter/X, Facebook profiles to contact records. |
| REQ-3.6.02 | **Could**  | Social listening: monitor brand mentions and competitor keywords (basic).                    |
| REQ-3.6.03 | **Could**  | Post scheduling and publishing to connected social accounts.                                 |

---

### Phase 4: Customer Service & Support

**Target Timeline:** Months 12–15

*Extend the CRM into post-sale customer service with ticketing, knowledge base, and SLA management. Modelled after Salesforce Service Cloud, HubSpot Service Hub, Zoho Desk, and Freshdesk.*

---

#### 4.1 Ticketing / Case Management

*Track and resolve customer issues.*

| Req ID     | Priority   | Requirement                                                                                                                                                                                                 |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-4.1.01 | **Must**   | Ticket/case entity with fields: subject, description, status (New, Open, Pending, On Hold, Resolved, Closed), priority (Low, Medium, High, Urgent), category, assignee, contact, company, and related deal. |
| REQ-4.1.02 | **Must**   | Ticket creation from: manual entry, email-to-ticket (dedicated support inbox), web form, chat, and API.                                                                                                     |
| REQ-4.1.03 | **Must**   | Ticket assignment rules: auto-assign based on category, round-robin, or manual.                                                                                                                             |
| REQ-4.1.04 | **Must**   | Internal notes on tickets (visible only to agents, not to the customer).                                                                                                                                    |
| REQ-4.1.05 | **Must**   | Reply-to-customer from ticket: send email response that threads into the ticket conversation.                                                                                                               |
| REQ-4.1.06 | **Should** | Ticket views: My Tickets, Unassigned, Overdue, By Priority, By Category with saved custom views.                                                                                                            |
| REQ-4.1.07 | **Should** | Ticket merging: combine duplicate tickets into one.                                                                                                                                                         |
| REQ-4.1.08 | **Should** | Ticket splitting: break a complex ticket into sub-tickets.                                                                                                                                                  |

---

#### 4.2 SLA Management

*Define and enforce service-level agreements.*

| Req ID     | Priority   | Requirement                                                                                    |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------- |
| REQ-4.2.01 | **Must**   | SLA policies with configurable response time and resolution time targets per priority level.   |
| REQ-4.2.02 | **Must**   | SLA countdown timers on tickets with visual indicators (green/yellow/red).                     |
| REQ-4.2.03 | **Should** | Escalation rules: auto-reassign or notify manager when SLA is about to breach or has breached. |
| REQ-4.2.04 | **Should** | SLA compliance reporting: % tickets resolved within SLA by period, team, and agent.            |
| REQ-4.2.05 | **Could**  | Business hours configuration: SLA timers respect working hours and holidays.                   |

---

#### 4.3 Knowledge Base

*Self-service help centre for customers. Based on Salesforce Knowledge, HubSpot Knowledge Base, and Zoho Desk KB.*

| Req ID     | Priority   | Requirement                                                                                                 |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------- |
| REQ-4.3.01 | **Must**   | Article editor with rich text, images, embedded video, and categorisation (categories and tags).            |
| REQ-4.3.02 | **Must**   | Public-facing knowledge base portal with search, browsing by category, and responsive design.               |
| REQ-4.3.03 | **Should** | Internal-only articles visible to agents but hidden from the public portal.                                 |
| REQ-4.3.04 | **Should** | Article helpfulness voting (thumbs up/down) with analytics.                                                 |
| REQ-4.3.05 | **Should** | Suggested articles: when a customer types a ticket subject, suggest relevant KB articles before submission. |
| REQ-4.3.06 | **Could**  | Article versioning and approval workflow before publishing.                                                 |

---

#### 4.4 Customer Portal

*Branded portal for customers to self-serve. Inspired by Salesforce Experience Cloud and Zoho Desk Portal.*

| Req ID     | Priority   | Requirement                                                                                       |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------- |
| REQ-4.4.01 | **Should** | Customer login portal where customers can view and update their own tickets.                      |
| REQ-4.4.02 | **Should** | Ticket submission form within the portal.                                                         |
| REQ-4.4.03 | **Could**  | Community forum: customers can post questions and receive answers from other customers or agents. |
| REQ-4.4.04 | **Could**  | Portal branding: custom domain, logo, colours, and CSS.                                           |

---

#### 4.5 Customer Feedback & Surveys

*Measure customer satisfaction. Based on Salesforce Feedback Management and HubSpot feedback tools.*

| Req ID     | Priority   | Requirement                                                                         |
| ---------- | ---------- | ----------------------------------------------------------------------------------- |
| REQ-4.5.01 | **Should** | CSAT (Customer Satisfaction) survey automatically sent after ticket resolution.     |
| REQ-4.5.02 | **Should** | NPS (Net Promoter Score) survey with score tracking over time.                      |
| REQ-4.5.03 | **Could**  | Custom survey builder with multiple question types (rating, text, multiple choice). |
| REQ-4.5.04 | **Could**  | Survey response analytics dashboard with trends and breakdown by agent/team.        |

---

### Phase 5: Advanced Analytics & Business Intelligence

**Target Timeline:** Months 16–18

*Provide deep analytics, custom report building, and revenue intelligence. Inspired by Salesforce Einstein Analytics, HubSpot Custom Reports, Zoho Analytics, and Microsoft Power BI integration.*

---

#### 5.1 Custom Report Builder

*Ad-hoc reporting for any data in the CRM.*

| Req ID     | Priority   | Requirement                                                                                                       |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------- |
| REQ-5.1.01 | **Must**   | Drag-and-drop report builder: select entity, fields (dimensions and measures), filters, grouping, and chart type. |
| REQ-5.1.02 | **Must**   | Cross-entity reports: join data across contacts, companies, deals, activities, tickets, and custom entities.      |
| REQ-5.1.03 | **Must**   | Chart types: bar, column, line, area, pie, donut, funnel, scatter, table/pivot, and number summary.               |
| REQ-5.1.04 | **Must**   | Save, name, and organise reports into folders with sharing permissions (private, team, organisation).             |
| REQ-5.1.05 | **Should** | Scheduled report delivery: email a report PDF/CSV on a recurring schedule.                                        |
| REQ-5.1.06 | **Should** | Report drill-down: click a chart segment to see underlying records.                                               |

---

#### 5.2 Advanced Dashboards

*Executive and operational dashboards.*

| Req ID     | Priority   | Requirement                                                                                      |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------ |
| REQ-5.2.01 | **Must**   | Dashboard builder: add multiple report widgets to a dashboard canvas with resize and reposition. |
| REQ-5.2.02 | **Must**   | Dashboard-level filters that apply across all widgets (e.g. date range, team, owner).            |
| REQ-5.2.03 | **Should** | Real-time dashboard with auto-refresh interval configuration.                                    |
| REQ-5.2.04 | **Should** | Goal/target lines on charts to compare actual vs. target.                                        |
| REQ-5.2.05 | **Could**  | Dashboard embedding: generate an iframe or public URL for external display (TV dashboards).      |

---

#### 5.3 Revenue & Pipeline Analytics

*Deep-dive into revenue performance.*

| Req ID     | Priority   | Requirement                                                                                                           |
| ---------- | ---------- | --------------------------------------------------------------------------------------------------------------------- |
| REQ-5.3.01 | **Must**   | Pipeline velocity report: average time in each stage, conversion rate between stages, and overall sales cycle length. |
| REQ-5.3.02 | **Should** | Win/loss analysis: win rate by source, product, rep, deal size, and time period.                                      |
| REQ-5.3.03 | **Should** | Revenue waterfall chart: starting pipeline + new deals – lost deals – won deals = ending pipeline.                    |
| REQ-5.3.04 | **Should** | Cohort analysis: track deal cohorts by creation month through to close.                                               |
| REQ-5.3.05 | **Could**  | Multi-touch revenue attribution: distribute deal revenue across all influencing campaigns.                            |

---

#### 5.4 Activity & Productivity Analytics

*Measure team performance and activity effectiveness.*

| Req ID     | Priority   | Requirement                                                                                      |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------ |
| REQ-5.4.01 | **Should** | Rep activity scorecards: calls made, emails sent, meetings booked, deals created/won per period. |
| REQ-5.4.02 | **Should** | Leaderboard widget: rank reps by configurable metrics (deals won, revenue, activities).          |
| REQ-5.4.03 | **Could**  | Activity-to-outcome correlation: which activity patterns lead to higher win rates.               |

---

### Phase 6: Integration Platform & Extensibility

**Target Timeline:** Months 19–22

*Open the CRM to the broader technology ecosystem with a robust API, pre-built integrations, and developer tools. Inspired by Salesforce AppExchange, HubSpot Marketplace, and Zapier connectivity.*

---

#### 6.1 REST API

*Programmatic access to all CRM data and operations.*

| Req ID     | Priority   | Requirement                                                                                                                                                   |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-6.1.01 | **Must**   | RESTful API covering CRUD operations for all entities (contacts, companies, leads, deals, activities, tickets, products, quotes, campaigns, custom entities). |
| REQ-6.1.02 | **Must**   | API authentication via OAuth 2.0 and API key methods.                                                                                                         |
| REQ-6.1.03 | **Must**   | Pagination, filtering, sorting, and field selection on all list endpoints.                                                                                    |
| REQ-6.1.04 | **Must**   | Rate limiting with clear headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After).                                                                     |
| REQ-6.1.05 | **Must**   | Comprehensive API documentation with interactive explorer (Swagger/OpenAPI).                                                                                  |
| REQ-6.1.06 | **Should** | Bulk API endpoints for batch create/update/delete operations.                                                                                                 |
| REQ-6.1.07 | **Should** | API versioning strategy with deprecation policy.                                                                                                              |

---

#### 6.2 Webhooks & Events

*Real-time event notifications to external systems.*

| Req ID     | Priority   | Requirement                                                                                                                   |
| ---------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------- |
| REQ-6.2.01 | **Must**   | Configurable webhooks: fire HTTP POST to a URL when specified events occur (record created, updated, deleted, stage changed). |
| REQ-6.2.02 | **Must**   | Webhook management UI: create, test, enable/disable, and view delivery logs with retry for failures.                          |
| REQ-6.2.03 | **Should** | Event payload includes: event type, entity type, record ID, changed fields (old/new values), timestamp, and actor.            |
| REQ-6.2.04 | **Could**  | Webhook signing (HMAC) for payload verification by the receiver.                                                              |

---

#### 6.3 Pre-built Integrations

*Out-of-the-box connectors to common tools.*

| Req ID     | Priority   | Requirement                                                                                            |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------ |
| REQ-6.3.01 | **Must**   | Google Workspace integration: two-way calendar sync, Gmail email logging, Google Contacts sync.        |
| REQ-6.3.02 | **Must**   | Microsoft 365 integration: Outlook calendar sync, email logging, OneDrive document linking.            |
| REQ-6.3.03 | **Should** | Slack integration: CRM notifications in Slack channels, record lookup via slash commands, deal alerts. |
| REQ-6.3.04 | **Should** | Zapier / Make (Integromat) connector: enable no-code integration with thousands of apps.               |
| REQ-6.3.05 | **Should** | Accounting integration: sync invoices and payments with QuickBooks, Xero, or similar.                  |
| REQ-6.3.06 | **Could**  | Telephony integration: click-to-call with VoIP providers (Twilio, RingCentral) with auto call logging. |
| REQ-6.3.07 | **Could**  | E-signature integration: DocuSign, Adobe Sign for quote/contract signing.                              |
| REQ-6.3.08 | **Could**  | LinkedIn Sales Navigator integration: view LinkedIn profiles and InMail from contact records.          |

---

#### 6.4 Data Migration & Sync

*Move data into and between systems.*

| Req ID     | Priority   | Requirement                                                                                                          |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------- |
| REQ-6.4.01 | **Must**   | Advanced import: support CSV, XLSX, JSON with field mapping, transformation rules, and scheduled recurring imports.  |
| REQ-6.4.02 | **Should** | Migration wizards for importing from Salesforce, HubSpot, Pipedrive, and Zoho with pre-built field mappings.         |
| REQ-6.4.03 | **Should** | Bi-directional sync engine for keeping data in sync between CRM and external systems with conflict resolution rules. |
| REQ-6.4.04 | **Could**  | Data mapping and transformation studio for complex ETL scenarios.                                                    |

---

#### 6.5 Mobile Application

*Native mobile experience for field sales.*

| Req ID     | Priority   | Requirement                                                                                                                        |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| REQ-6.5.01 | **Must**   | Native mobile app (iOS and Android) with core CRM features: view/edit contacts, companies, deals; log activities; access calendar. |
| REQ-6.5.02 | **Must**   | Push notifications for task reminders, deal updates, and assignment changes.                                                       |
| REQ-6.5.03 | **Should** | Offline mode: view recently accessed records and queue changes for sync when connectivity returns.                                 |
| REQ-6.5.04 | **Should** | Mobile business card scanner: photograph a business card and auto-create a contact record via OCR.                                 |
| REQ-6.5.05 | **Could**  | Geo-location features: nearby contacts/companies, check-in at a location.                                                          |

---

### Phase 7: AI & Intelligent Automation

**Target Timeline:** Months 23–26

*Embed artificial intelligence throughout the CRM for predictive insights, content generation, and intelligent automation. Inspired by Salesforce Einstein, HubSpot Breeze AI, Zoho Zia, and Microsoft Dynamics Copilot.*

---

#### 7.1 AI Lead & Deal Scoring

*Predictive scoring to prioritise the best opportunities.*

| Req ID     | Priority   | Requirement                                                                                                                |
| ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------------- |
| REQ-7.1.01 | **Must**   | AI-powered lead score (0–100) based on demographic fit, engagement signals, and historical conversion patterns.            |
| REQ-7.1.02 | **Must**   | AI-powered deal score predicting probability of close based on deal attributes, activity history, and pipeline patterns.   |
| REQ-7.1.03 | **Should** | Score explanation: display the top factors contributing to each score (e.g. "High engagement: 5 emails opened this week"). |
| REQ-7.1.04 | **Should** | Model retraining on a configurable schedule as new win/loss data accumulates.                                              |

---

#### 7.2 AI Sales Assistant / Copilot

*Conversational AI to help sales reps work faster.*

| Req ID     | Priority   | Requirement                                                                                                                                      |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| REQ-7.2.01 | **Should** | In-app AI assistant (chat interface) that can answer questions about CRM data (e.g. "What deals close this month?", "Show me my overdue tasks"). |
| REQ-7.2.02 | **Should** | AI-generated email drafts: suggest reply content based on conversation history and deal context.                                                 |
| REQ-7.2.03 | **Should** | AI meeting preparation: generate a briefing note before a meeting summarising the contact's history, deal status, and recent interactions.       |
| REQ-7.2.04 | **Could**  | AI next-best-action recommendations: suggest what action to take next on a deal (call, send proposal, schedule demo).                            |

---

#### 7.3 Conversation Intelligence

*Extract insights from sales conversations.*

| Req ID     | Priority   | Requirement                                                                                                            |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------------- |
| REQ-7.3.01 | **Should** | Call transcription: automatically transcribe recorded sales calls and link transcripts to the contact/deal record.     |
| REQ-7.3.02 | **Should** | Sentiment analysis on emails and call transcripts to flag at-risk deals.                                               |
| REQ-7.3.03 | **Could**  | Key moment extraction: identify competitor mentions, pricing discussions, objections, and next steps from transcripts. |
| REQ-7.3.04 | **Could**  | Coaching insights: talk-to-listen ratio, longest monologue, question frequency for manager review.                     |

---

#### 7.4 Predictive Analytics & Anomaly Detection

*AI-driven forecasting and alerting.*

| Req ID     | Priority   | Requirement                                                                                                                                      |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| REQ-7.4.01 | **Should** | AI-enhanced sales forecasting: predict quarterly revenue with confidence intervals based on historical trends and current pipeline.              |
| REQ-7.4.02 | **Should** | Churn risk scoring for existing customers based on engagement decline, support ticket patterns, and usage data.                                  |
| REQ-7.4.03 | **Could**  | Anomaly detection: alert when metrics deviate significantly from normal patterns (e.g. sudden drop in lead volume, unusual spike in lost deals). |
| REQ-7.4.04 | **Could**  | AI content generation for marketing emails, blog outlines, and social posts using CRM data as context.                                           |

---

### Phase 8: Enterprise Features & Scale

**Target Timeline:** Months 27–32+

*Enterprise-grade capabilities for large, global, and regulated organisations. Inspired by Salesforce Enterprise/Unlimited editions, Microsoft Dynamics 365 Enterprise, and HubSpot Enterprise features.*

---

#### 8.1 Multi-Currency & Internationalisation

| Req ID     | Priority   | Requirement                                                                                          |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------------- |
| REQ-8.1.01 | **Must**   | Multi-currency support: configure available currencies with exchange rates (manual or auto-updated). |
| REQ-8.1.02 | **Must**   | Deals and quotes display values in both the deal currency and the corporate (reporting) currency.    |
| REQ-8.1.03 | **Should** | Multi-language UI: support for multiple interface languages with user-selectable preference.         |
| REQ-8.1.04 | **Should** | Multi-timezone handling: all timestamps stored in UTC, displayed in user's local timezone.           |

---

#### 8.2 Territory Management

| Req ID     | Priority   | Requirement                                                                                                      |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------- |
| REQ-8.2.01 | **Should** | Define sales territories by geography (country, region, postal code), industry, company size, or named accounts. |
| REQ-8.2.02 | **Should** | Auto-assign leads and accounts to territories based on rules.                                                    |
| REQ-8.2.03 | **Could**  | Territory hierarchy with rollup reporting.                                                                       |

---

#### 8.3 Advanced Approval Workflows

| Req ID     | Priority   | Requirement                                                                          |
| ---------- | ---------- | ------------------------------------------------------------------------------------ |
| REQ-8.3.01 | **Should** | Multi-step approval processes: sequential, parallel, and conditional approvers.      |
| REQ-8.3.02 | **Should** | Approval rules triggered by field values (e.g. discount > 20% requires VP approval). |
| REQ-8.3.03 | **Should** | Approval via email: approve/reject directly from the notification email.             |
| REQ-8.3.04 | **Could**  | Delegation: auto-reroute approvals when an approver is out of office.                |

---

#### 8.4 Compliance, Audit & Data Governance

| Req ID     | Priority   | Requirement                                                                                                                                          |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-8.4.01 | **Must**   | Comprehensive audit trail: log all data access, changes, exports, and login events with retention policy.                                            |
| REQ-8.4.02 | **Must**   | GDPR compliance tools: data subject access request (DSAR) export, right to erasure (data deletion), consent management, and data processing records. |
| REQ-8.4.03 | **Should** | Data retention policies: auto-archive or delete records after a configurable period.                                                                 |
| REQ-8.4.04 | **Should** | IP allowlisting and login hour restrictions per role.                                                                                                |
| REQ-8.4.05 | **Could**  | Sandbox/staging environment: clone the CRM instance for testing changes before production deployment.                                                |

---

#### 8.5 Partner Relationship Management (PRM)

| Req ID     | Priority  | Requirement                                                                                                         |
| ---------- | --------- | ------------------------------------------------------------------------------------------------------------------- |
| REQ-8.5.01 | **Could** | Partner portal: external partners can log in, register deals, access co-branded materials, and view their pipeline. |
| REQ-8.5.02 | **Could** | Partner deal registration with approval workflow to prevent channel conflict.                                       |
| REQ-8.5.03 | **Could** | Partner performance dashboards: deals registered, converted, revenue by partner.                                    |

---

#### 8.6 Field Service Management

| Req ID     | Priority  | Requirement                                                                                                    |
| ---------- | --------- | -------------------------------------------------------------------------------------------------------------- |
| REQ-8.6.01 | **Could** | Work order entity linked to tickets, contacts, and assets with scheduling and dispatch capabilities.           |
| REQ-8.6.02 | **Could** | Technician mobile app with route optimisation, job checklist, time tracking, and customer sign-off.            |
| REQ-8.6.03 | **Could** | Asset/equipment tracking: maintain a register of customer assets with warranty, service history, and IoT data. |

---

#### 8.7 Commerce & Order Management

| Req ID     | Priority  | Requirement                                                                                                          |
| ---------- | --------- | -------------------------------------------------------------------------------------------------------------------- |
| REQ-8.7.01 | **Could** | Order entity: convert accepted quotes into orders with fulfilment tracking (Ordered, Shipped, Delivered, Cancelled). |
| REQ-8.7.02 | **Could** | Invoice generation from orders with payment status tracking.                                                         |
| REQ-8.7.03 | **Could** | Subscription management: track recurring subscriptions with renewal date alerts and usage metrics.                   |

---

## 5. Non-Functional Requirements

### 5.1 Performance

- **NFR-01:** Page load time under 2 seconds for standard list and record views (P95).
- **NFR-02:** API response time under 500ms for single-record operations (P95).
- **NFR-03:** Support for at least 500 concurrent users without degradation.
- **NFR-04:** Search results returned within 1 second for databases up to 5 million records.

### 5.2 Scalability

- **NFR-05:** Horizontal scalability: application tier must support auto-scaling behind a load balancer.
- **NFR-06:** Database must handle at least 10 million contact records and 5 million deal records.
- **NFR-07:** File storage must scale to at least 1TB of documents and attachments.

### 5.3 Availability & Reliability

- **NFR-08:** Target uptime of 99.9% (excluding planned maintenance windows).
- **NFR-09:** Automated daily backups with point-in-time recovery capability.
- **NFR-10:** Disaster recovery plan with RTO < 4 hours and RPO < 1 hour.

### 5.4 Security

- **NFR-11:** All data encrypted in transit (TLS 1.2+) and at rest (AES-256).
- **NFR-12:** OWASP Top 10 compliance: protection against injection, XSS, CSRF, and other common vulnerabilities.
- **NFR-13:** Regular security audits and penetration testing (at least annually).
- **NFR-14:** Session management: configurable session timeout, concurrent session limits.

### 5.5 Usability & Accessibility

- **NFR-15:** Responsive design supporting desktop (1280px+), tablet (768px+), and mobile (320px+) viewports.
- **NFR-16:** WCAG 2.1 Level AA accessibility compliance.
- **NFR-17:** Consistent UI patterns, design system, and component library across all modules.
- **NFR-18:** Contextual help tooltips and link to documentation on every major screen.

### 5.6 Maintainability & DevOps

- **NFR-19:** Modular architecture allowing phases to be developed and deployed independently.
- **NFR-20:** CI/CD pipeline with automated testing (unit, integration, end-to-end).
- **NFR-21:** Structured logging, error tracking, and application performance monitoring (APM).
- **NFR-22:** Feature flags to enable/disable features per environment and per tenant.

---

## 6. Competitive Feature Matrix

The table below maps the CRM's planned capabilities to the features offered by the five leading CRM platforms analysed during requirements gathering. This ensures comprehensive feature coverage.

| Capability                   | Salesforce |  HubSpot   | Dynamics 365 | Zoho CRM | Pipedrive |
| ---------------------------- | :--------: | :--------: | :----------: | :------: | :-------: |
| Contact & Company Mgmt       |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Lead Mgmt & Scoring          |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Deal Pipeline (Kanban)       |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Activity & Task Mgmt         |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Email Integration & Tracking |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Workflow Automation          |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Email Sequences              |     ✓      |     ✓      |    Add-on    |    ✓     |     ✓     |
| Quote / CPQ                  |     ✓      |     ✓      |      ✓       |    ✓     |  Add-on   |
| Product Catalogue            |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Sales Forecasting            |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Campaign Management          |     ✓      |     ✓      |      ✓       |    ✓     |  Add-on   |
| Email Marketing              |   Add-on   |     ✓      |    Add-on    |    ✓     |  Add-on   |
| Landing Pages & Forms        |   Add-on   |     ✓      |    Add-on    |    ✓     |     ✗     |
| Live Chat & Chatbot          |     ✓      |     ✓      |    Add-on    |    ✓     |  Add-on   |
| Ticketing / Help Desk        |     ✓      |     ✓      |      ✓       | ✓ (Desk) |     ✗     |
| Knowledge Base               |     ✓      |     ✓      |      ✓       |    ✓     |     ✗     |
| SLA Management               |     ✓      |     ✓      |      ✓       |    ✓     |     ✗     |
| Customer Portal              |     ✓      |     ✓      |      ✓       |    ✓     |     ✗     |
| Custom Report Builder        |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| REST API                     |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Mobile App                   |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| AI Lead Scoring              |     ✓      |     ✓      |      ✓       | ✓ (Zia)  |     ✓     |
| AI Copilot / Assistant       |     ✓      | ✓ (Breeze) | ✓ (Copilot)  | ✓ (Zia)  |     ✓     |
| Multi-Currency               |     ✓      |     ✓      |      ✓       |    ✓     |     ✓     |
| Territory Management         |     ✓      |     ✗      |      ✓       |    ✓     |     ✗     |
| Partner Portal (PRM)         |     ✓      |     ✗      |      ✓       |    ✓     |     ✗     |
| Field Service                |     ✓      |     ✗      |      ✓       |    ✗     |     ✗     |

*✓ = Native feature included  |  Add-on = Available as paid add-on or separate module  |  ✗ = Not available natively*

---

## 7. Requirements Summary

### Overall Totals

| Total Requirements | Must Have | Should Have | Could Have |
| :----------------: | :-------: | :---------: | :--------: |
|      **262**       |  **113**  |   **96**    |   **53**   |

### Requirements per Phase

| Phase                                    | Must  | Should | Could | Total | Modules |
| ---------------------------------------- | :---: | :----: | :---: | :---: | :-----: |
| Phase 1: Core CRM Foundation (MVP)       |  42   |   16   |   7   |  65   |    9    |
| Phase 2: Sales Automation & Productivity |  21   |   18   |   8   |  47   |    8    |
| Phase 3: Marketing & Communication       |  10   |   14   |   9   |  33   |    6    |
| Phase 4: Customer Service & Support      |   9   |   13   |   7   |  29   |    5    |
| Phase 5: Advanced Analytics & BI         |   7   |   9    |   3   |  19   |    4    |
| Phase 6: Integration Platform            |  12   |   10   |   7   |  29   |    5    |
| Phase 7: AI & Intelligent Automation     |   2   |   10   |   4   |  16   |    4    |
| Phase 8: Enterprise Features & Scale     |   4   |   10   |  10   |  24   |    7    |

---

## 8. Glossary

| Term   | Definition                                                                                    |
| ------ | --------------------------------------------------------------------------------------------- |
| CRM    | Customer Relationship Management                                                              |
| MVP    | Minimum Viable Product — the smallest set of features that delivers value and enables go-live |
| RBAC   | Role-Based Access Control                                                                     |
| CRUD   | Create, Read, Update, Delete                                                                  |
| SLA    | Service Level Agreement                                                                       |
| CSAT   | Customer Satisfaction Score                                                                   |
| NPS    | Net Promoter Score                                                                            |
| CPQ    | Configure, Price, Quote                                                                       |
| ETL    | Extract, Transform, Load                                                                      |
| PRM    | Partner Relationship Management                                                               |
| GDPR   | General Data Protection Regulation                                                            |
| WCAG   | Web Content Accessibility Guidelines                                                          |
| API    | Application Programming Interface                                                             |
| OCR    | Optical Character Recognition                                                                 |
| MoSCoW | Must, Should, Could, Won't — prioritisation framework                                         |

---

*— End of Document —*