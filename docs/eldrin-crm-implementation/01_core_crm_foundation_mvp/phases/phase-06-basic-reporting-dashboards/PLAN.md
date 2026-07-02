# Phase 6: Basic Reporting & Dashboards

## Overview

Build out-of-the-box reports and dashboards that give sales teams immediate visibility into pipeline health, activity levels, lead sources, and key performance indicators. All report endpoints support date range filtering (today, this_week, this_month, this_quarter, this_year, custom). Charts use Recharts with full dark mode support. CSV export is included for all report types.

Covers requirements REQ-1.5.01 through REQ-1.5.08.

## Dependencies

- **Phase 02** — Contact and company data (for activity-by-contact reports)
- **Phase 03** — Lead data (for lead source and conversion reports)
- **Phase 04** — Deal and pipeline data (for pipeline funnel, won/lost reports)
- **Phase 05** — Activity data (for activity summary reports)

## Steps

### 6.1 Create report data endpoints

Create `worker/routes/reports.ts` with the following endpoints:

- `GET /api/reports/dashboard` — aggregated KPIs for the current period:
  - Open deals count and total value
  - Deals won and lost this period (count + value)
  - Lead-to-deal conversion rate
  - Activities completed
  - New leads created
- `GET /api/reports/pipeline-funnel?pipeline_id=X` — deal count and value per stage for a given pipeline
- `GET /api/reports/activity-summary` — activities grouped by type, by user, and by date range
- `GET /api/reports/lead-sources` — leads grouped by source with conversion rate per source

All endpoints accept query parameters:
- `period` — one of `today`, `this_week`, `this_month`, `this_quarter`, `this_year`, `custom`
- `start_date` / `end_date` — ISO date strings for custom range
- `pipeline_id` — filter by pipeline (where applicable)
- `user_id` — filter by assigned user (where applicable)

### 6.2 Implement report query service

Create `worker/services/reports.ts` with aggregation query functions using Drizzle:

- `getDashboardKPIs(db, filters)` — multiple COUNT/SUM queries across deals, leads, activities
- `getPipelineFunnel(db, pipelineId, filters)` — GROUP BY stage with count and sum of deal value
- `getActivitySummary(db, filters)` — GROUP BY activity type, GROUP BY user_id, daily/weekly counts
- `getLeadSourceReport(db, filters)` — GROUP BY source with conversion rate calculation (leads that became deals / total leads)
- `buildDateFilter(period, startDate, endDate)` — utility to convert period presets into SQL date range conditions using epoch timestamps

### 6.3 Build dashboard page

Create `src/pages/reports/Dashboard.tsx`:

- Responsive grid layout (2 columns on desktop, 1 on mobile)
- Row of KPI number cards at the top: open deals, pipeline value, deals won, deals lost, conversion rate, activities completed, new leads
- Pipeline funnel chart below KPIs
- Activity trend line chart (activities per day over the selected period)
- Lead source pie chart
- Period selector component controlling all widgets

### 6.4 Build pipeline funnel chart component

Create `src/components/reports/PipelineFunnel.tsx`:

- Recharts `FunnelChart` showing each pipeline stage as a funnel segment
- Display deal count and total value per stage
- Color-coded segments (consistent with pipeline stage colors from Phase 04)
- Tooltip showing stage name, deal count, total value, and percentage of total
- Pipeline selector dropdown when multiple pipelines exist

### 6.5 Build activity report page

Create `src/pages/reports/ActivityReport.tsx`:

- Bar chart: activities grouped by type (call, email, meeting, task, note)
- Table: activities grouped by user with count per type
- Line chart: activity trend over the selected date range (daily or weekly aggregation)
- Filter controls: date range, user, activity type

### 6.6 Build lead source report page

Create `src/pages/reports/LeadSourceReport.tsx`:

- Pie chart: leads grouped by source
- Table with columns: source, lead count, converted count, conversion rate percentage
- Bar chart: conversion rate by source (sorted descending)
- Filter controls: date range

### 6.7 Build date range filter component

Create `src/components/reports/DateRangeFilter.tsx`:

- Preset buttons: Today, This Week, This Month, This Quarter, This Year
- Custom date range picker with start and end date inputs
- Active preset highlighted with daisyUI `btn-primary`
- Emits `{ period, startDate?, endDate? }` on change
- Stores last-used period in component state (or URL search params)

### 6.8 Build reusable chart widget components

Create chart components in `src/components/reports/`:

- `NumberCard.tsx` — KPI display with label, value, optional trend indicator (up/down arrow with percentage)
- `BarChartWidget.tsx` — wrapper around Recharts `BarChart` with consistent styling, tooltips, responsive container
- `LineChartWidget.tsx` — wrapper around Recharts `LineChart` with consistent styling, grid lines, responsive container
- `PieChartWidget.tsx` — wrapper around Recharts `PieChart` with legend, tooltips, responsive container
- `LeaderboardWidget.tsx` — ranked list component (e.g., top sales reps by deals won)

All widgets must:
- Respect daisyUI theme colors (use CSS variables for chart colors)
- Show loading skeleton while data is fetching
- Handle empty state with a helpful message

### 6.9 Implement CSV export endpoint

Create `GET /api/reports/export` with query parameters:
- `type` — one of `dashboard`, `pipeline_funnel`, `activity_summary`, `lead_sources`
- `format` — `csv` (PDF is a stretch goal, not required for MVP)
- Same date range and filter parameters as the corresponding report endpoint

Implementation in `worker/services/csv-export.ts`:
- Convert report data to CSV format with proper header row
- Handle special characters and quoting (RFC 4180)
- Return with `Content-Type: text/csv` and `Content-Disposition: attachment; filename="report-name-YYYY-MM-DD.csv"`

Add export button to each report page that triggers CSV download.

### 6.10 Wire up report routes and navigation

- Register report routes in `worker/index.ts`
- Add report pages to the frontend router in `src/root.component.tsx`:
  - `/eldrin-crm/reports` — Dashboard (default)
  - `/eldrin-crm/reports/pipeline` — Pipeline funnel
  - `/eldrin-crm/reports/activities` — Activity summary
  - `/eldrin-crm/reports/leads` — Lead source report
- Add sub-navigation within the Reports section (tab-style links)
- Create `src/stores/reportStore.ts` — Zustand store for shared report state (selected period, filters)

## Test Gate

```bash
cd eldrin-crm && npm run build   # Zero TypeScript errors
cd eldrin-crm && npm run test    # Report service tests pass
```

Acceptance criteria:
1. Dashboard page renders all 7 KPI cards with real data from the database
2. Pipeline funnel chart displays stages with correct deal counts and values
3. Activity report shows bar chart by type, table by user, and trend line
4. Lead source report shows pie chart and conversion rate table
5. Date range filtering works across all report endpoints and UI components
6. CSV export produces a valid, downloadable CSV file with correct headers and data
7. All charts render correctly in dark mode (no invisible text, proper contrast)
8. Empty states display correctly when no data exists for the selected period
9. Report pages are responsive (readable on tablet-width screens)

## Files Created

| File | Purpose |
|------|---------|
| `worker/routes/reports.ts` | Report data API endpoints (dashboard, funnel, activity, leads) |
| `worker/services/reports.ts` | Aggregation query functions with Drizzle |
| `worker/services/csv-export.ts` | CSV generation and formatting service |
| `src/pages/reports/Dashboard.tsx` | Main dashboard page with KPI cards and charts |
| `src/pages/reports/ActivityReport.tsx` | Activity summary report page |
| `src/pages/reports/LeadSourceReport.tsx` | Lead source and conversion report page |
| `src/components/reports/PipelineFunnel.tsx` | Recharts funnel chart component |
| `src/components/reports/DateRangeFilter.tsx` | Period selector with presets and custom range |
| `src/components/reports/NumberCard.tsx` | KPI display card with trend indicator |
| `src/components/reports/BarChartWidget.tsx` | Reusable bar chart wrapper |
| `src/components/reports/LineChartWidget.tsx` | Reusable line chart wrapper |
| `src/components/reports/PieChartWidget.tsx` | Reusable pie chart wrapper |
| `src/components/reports/LeaderboardWidget.tsx` | Ranked list widget |
| `src/stores/reportStore.ts` | Zustand store for shared report filters and state |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Register report routes |
| `src/root.component.tsx` | Add report page routes and sub-navigation |

## Finalize

- [ ] Manual validation: dashboard loads with KPI data, charts render, date range filter works
- [ ] Manual validation: CSV export downloads valid file for each report type
- [ ] Manual validation: dark mode renders all charts with correct colors and contrast
- [ ] Commit: `feat(crm): add reporting dashboards with KPIs, funnel, activity, and lead source reports`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
