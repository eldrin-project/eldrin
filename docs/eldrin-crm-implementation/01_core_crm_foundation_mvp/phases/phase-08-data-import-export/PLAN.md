# Phase 8: Data Import & Export

## Overview

Enable users to migrate data into the CRM from CSV files and extract data for external use. The import flow is a multi-step wizard with field mapping, duplicate detection, preview, progress tracking, and rollback capability. Export supports field selection and filter criteria. All four core entity types are supported: contacts, companies, leads, and deals.

Covers requirements REQ-1.7.01 through REQ-1.7.05.

## Dependencies

- **Phase 02** — Contacts and companies (entities to import/export, duplicate detection service)
- **Phase 03** — Leads (entity to import/export)
- **Phase 04** — Deals (entity to import/export)

## Steps

### 8.1 Create import/export database migration

Create `migrations/006-import-export.sql` with the following tables:

**`import_jobs`**:
- `id` TEXT PRIMARY KEY (ULID)
- `entity_type` TEXT NOT NULL (contacts/companies/leads/deals)
- `file_name` TEXT NOT NULL
- `total_rows` INTEGER NOT NULL DEFAULT 0
- `processed_rows` INTEGER NOT NULL DEFAULT 0
- `created_rows` INTEGER NOT NULL DEFAULT 0
- `updated_rows` INTEGER NOT NULL DEFAULT 0
- `skipped_rows` INTEGER NOT NULL DEFAULT 0
- `failed_rows` INTEGER NOT NULL DEFAULT 0
- `status` TEXT NOT NULL DEFAULT 'pending' (pending/mapping/previewing/processing/completed/failed/rolled_back)
- `duplicate_handling` TEXT NOT NULL DEFAULT 'skip' (skip/overwrite/flag)
- `field_mapping` TEXT (JSON: `{ csvColumn: entityField }`)
- `error_log` TEXT (JSON array of error objects)
- `created_by` TEXT NOT NULL
- `created_at` INTEGER NOT NULL
- `completed_at` INTEGER

**`import_job_records`**:
- `id` TEXT PRIMARY KEY (ULID)
- `import_job_id` TEXT NOT NULL (FK to import_jobs)
- `row_number` INTEGER NOT NULL
- `record_id` TEXT (nullable, the created/updated record ID)
- `action` TEXT NOT NULL (created/updated/skipped/failed)
- `error` TEXT (nullable, error message for failed rows)

Add indexes on `import_job_records(import_job_id)`, `import_jobs(status)`, `import_jobs(created_by)`.

### 8.2 Add Drizzle schema

Create `worker/db/schema-import.ts` with Drizzle table definitions matching the migration. Re-export from `worker/db/schema.ts`.

### 8.3 Create import routes

Create `worker/routes/import-export.ts`:

- `POST /api/import/upload` — accept CSV file via multipart form data
  - Parse CSV headers (first row)
  - Create import_job record with status `mapping`
  - Return job ID, detected column names, and row count
- `POST /api/import/:jobId/preview` — accept field mapping configuration
  - Body: `{ fieldMapping: { csvColumn: entityField }, duplicateHandling: 'skip'|'overwrite'|'flag' }`
  - Store field mapping on import_job
  - Process first 10 rows through the mapping engine
  - Return preview data showing how CSV values map to entity fields
  - Update status to `previewing`
- `POST /api/import/:jobId/execute` — run the full import
  - Process all rows: parse, map fields, check duplicates, create/update records
  - Track progress: update `processed_rows` on import_job periodically
  - Record each row result in `import_job_records`
  - Update status to `completed` (or `failed` if critical error)
  - Return final counts: created, updated, skipped, failed
- `GET /api/import/history` — list past import jobs for the current user
  - Paginated, sorted by created_at descending
  - Include summary counts and status
- `POST /api/import/:jobId/rollback` — delete all records created by this import
  - Query `import_job_records` where action = `created`
  - Delete each record from its entity table
  - Update import_job status to `rolled_back`

### 8.4 Create export routes

Add to `worker/routes/import-export.ts`:

- `POST /api/export` — generate and download CSV
  - Body: `{ entityType, fields: string[], filters?: object, sort?: object }`
  - Query the entity table with filters and field selection
  - Generate CSV with selected fields as columns
  - Return with `Content-Type: text/csv` and `Content-Disposition: attachment`

### 8.5 Implement CSV parser service

Create `worker/services/csv-parser.ts`:

- `parseCSV(content: string)` — parse CSV text into rows
  - Handle quoted fields (RFC 4180 compliance)
  - Handle escaped quotes within fields
  - Handle newlines within quoted fields
  - Detect and skip BOM (byte order mark)
  - Return `{ headers: string[], rows: string[][] }`
- `parseCSVStream(readable: ReadableStream)` — streaming parser for large files
- `generateCSV(headers: string[], rows: string[][])` — generate CSV text from data
  - Properly quote fields containing commas, quotes, or newlines

### 8.6 Implement field mapping engine

Create `worker/services/field-mapper.ts`:

- `mapRow(row: string[], headers: string[], mapping: Record<string, string>, entityType: string)` — map a CSV row to an entity object
  - Apply the column-to-field mapping
  - Apply type transformations:
    - Date strings → epoch integers
    - Phone number normalization (strip non-digits, add country code heuristic)
    - Email validation and lowercasing
    - Numeric string → number (for deal values, etc.)
    - Boolean detection (yes/no, true/false, 1/0)
  - Return `{ data: object, warnings: string[] }`
- `suggestMapping(csvHeaders: string[], entityType: string)` — auto-suggest field mappings based on header name similarity (e.g., "First Name" → `first_name`, "Email Address" → `email`)
- `getEntityFields(entityType: string)` — return list of fields with types for the given entity

### 8.7 Implement duplicate handling in import

For each imported row:
1. Run the duplicate detection service from Phase 02 (email match for contacts, domain match for companies, etc.)
2. Based on `duplicate_handling` strategy:
   - `skip` — if duplicate found, record as `skipped` in import_job_records
   - `overwrite` — if duplicate found, update existing record with imported data, record as `updated`
   - `flag` — if duplicate found, create record anyway but add a `_duplicate_flag` tag for manual review
3. If no duplicate: create new record, record as `created`

### 8.8 Implement import rollback

In the rollback handler:
- Query all `import_job_records` where `action = 'created'` for the given job
- For each record: delete from the entity table by `record_id`
- Update import_job_records action to `rolled_back` (or delete them)
- Update import_job status to `rolled_back`
- Return count of records deleted

### 8.9 Build import wizard UI

Create `src/pages/import-export/ImportWizard.tsx` with a multi-step wizard:

**Step 1 — Upload**: File drop zone + entity type selector (contacts/companies/leads/deals). Upload CSV via `POST /api/import/upload`.

**Step 2 — Field Mapping**: Two-column layout showing CSV columns on the left and entity field dropdowns on the right. Auto-suggested mappings pre-selected. Unmapped columns shown with warning. Required fields highlighted.

**Step 3 — Duplicate Handling**: Radio buttons for skip/overwrite/flag strategy. Explanation text for each option.

**Step 4 — Preview**: Table showing first 10 rows with mapped values. Warnings highlighted in yellow. Errors highlighted in red. "Looks good" / "Go back" buttons.

**Step 5 — Execute**: Progress bar showing `processed_rows / total_rows`. Status text: "Importing row N of M...". Disable navigation during import.

**Step 6 — Results**: Summary cards: created (green), updated (blue), skipped (yellow), failed (red). Error details expandable for failed rows. "Download error report" button for failed rows. Rollback button (with confirmation dialog).

### 8.10 Build export dialog

Create `src/components/import-export/ExportDialog.tsx`:

- Modal/drawer triggered from entity list pages
- Entity type pre-selected based on current page
- Field selection: checkboxes for each entity field, select all/none
- Filter summary: show currently active filters (from the list page)
- Export button that triggers download
- Loading state while generating CSV

### 8.11 Build import history page

Create `src/pages/import-export/ImportHistory.tsx`:

- Table listing past import jobs: entity type, file name, status, row counts, date, user
- Status badges: completed (green), failed (red), rolled_back (gray), processing (blue spinner)
- Click to expand: detailed row-level results
- Rollback button for completed imports (with confirmation)
- Filter by entity type and status

## Test Gate

```bash
cd eldrin-crm && npm run build   # Zero TypeScript errors
cd eldrin-crm && npm run test    # Import/export service tests pass
```

Acceptance criteria:
1. CSV import for contacts: upload file, map fields, preview, execute, verify records created
2. CSV import for companies, leads, and deals: same flow works for all entity types
3. Field mapping UI: auto-suggest works, manual mapping dropdown works, required fields enforced
4. Duplicate handling: skip mode skips existing, overwrite mode updates, flag mode creates with tag
5. Export: select fields, apply filters, download CSV with correct headers and data
6. Import rollback: rollback deletes created records, job status updates to rolled_back
7. Import history: shows past jobs with accurate counts, rollback available for completed imports
8. Large file handling: 1000+ row CSV imports without timeout or memory issues

## Files Created

| File | Purpose |
|------|---------|
| `migrations/006-import-export.sql` | Import job tracking tables |
| `worker/db/schema-import.ts` | Drizzle schema for import tables |
| `worker/routes/import-export.ts` | Import upload/preview/execute/rollback and export endpoints |
| `worker/services/csv-parser.ts` | CSV parsing and generation (RFC 4180) |
| `worker/services/field-mapper.ts` | Field mapping engine with type transformations |
| `src/pages/import-export/ImportWizard.tsx` | Multi-step import wizard (6 steps) |
| `src/components/import-export/ExportDialog.tsx` | Export field selection and download dialog |
| `src/pages/import-export/ImportHistory.tsx` | Past import jobs list with rollback |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Re-export import schema tables |
| `worker/index.ts` | Register import/export routes |
| `src/root.component.tsx` | Add import wizard, import history, and export routes |
| `src/pages/contacts/ContactList.tsx` | Add "Import" and "Export" buttons |
| `src/pages/companies/CompanyList.tsx` | Add "Import" and "Export" buttons |
| `src/pages/leads/LeadList.tsx` | Add "Import" and "Export" buttons |
| `src/pages/deals/DealList.tsx` | Add "Import" and "Export" buttons |

## Finalize

- [ ] Manual validation: import 50-row contact CSV end-to-end, verify all records created
- [ ] Manual validation: field mapping auto-suggest picks correct mappings for standard CSV headers
- [ ] Manual validation: duplicate handling skip/overwrite/flag each work as documented
- [ ] Manual validation: export CSV with field selection, open in spreadsheet, verify correctness
- [ ] Manual validation: rollback deletes all created records from the import
- [ ] Commit: `feat(crm): add CSV import wizard and data export with field mapping and rollback`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
