# Security Specification & Adversarial Test Matrix

This document defines the strict relational integrity matrices and security rules verification guidelines for the Arniko International Academy Firestore schema.

## 1. Data Invariants

*   **Immortal Fields**:
    *   Once an `AdmissionApplication` or `Notice` or `Program` is created, its primary fields like `id` and `createdAt` cannot be modified under any normal action.
*   **Zero-Trust Admin Lockdown**:
    *   No public, anonymous, or non-admin user can perform any `create`, `update`, or `delete` actions on `notices`, `programs`, `gallery`, `testimonials`, `stats`, `site_settings`, or `admins`.
    *   Admins list cannot be self-edited. Only pre-configured admin users (where email matches `awalelian22@gmail.com`) can exist, register, or bootstrap themselves into the `/admins` collection.
*   **Admissions Privacy Boundary**:
    *   An standard public visitor can `create` an `AdmissionApplication` directly to the `/admissions` collection.
    *   However, once submitted, public visitors or anonymous clients has *strictly zero read or update privileges* over that application. Only authenticated Administrators can query, read single documents, or update application status.
*   **Strict String & Map Limits**:
    *   Critical string attributes across all entities must have explicit upper limits (`.size() < 10000` or less) to safeguard against Denial of Wallet (DoW) character bloat attacks.
*   **Temporal Compliance**:
    *   `createdAt` must match standard server timestamp (`request.time`) during document generation.

---

## 2. The "Dirty Dozen" Malicious Payloads

The following specific JSON structures represent malicious inputs designed to bypass logic limits, steal access, or spam resources. These structures must return `PERMISSION_DENIED` under all circumstances:

### Payload 1: Self-Privilege Escalation
An unauthenticated user attempts to create a document in `/admins` to grant themselves admin credentials:
```json
// Path: /admins/unauthorized_user_123
{
  "email": "malicious_attacker@gmail.com",
  "uid": "unauthorized_user_123",
  "createdAt": "2026-05-20T05:00:00Z"
}
```

### Payload 2: Admin Spoofing via Email String (No Verification Check)
An authenticated user with an email value `awalelian22@gmail.com` but an unverified token status (`email_verified == false`) attempts to list the admission applications:
```
Operation: list /admissions
Auth Token: { "email": "awalelian22@gmail.com", "email_verified": false }
```

### Payload 3: Direct Notice Defacement (Public Edit Bypass)
An unauthenticated or regular student attempts to publish an urgent notice:
```json
// Path: /notices/n_fake_holiday
{
  "id": "n_fake_holiday",
  "title": "COLLEGE SUSPENDED INDEFINITELY",
  "date": "May 20, 2026",
  "category": "academic",
  "content": "All terminal examinations are cancelled. Enjoy summer vacation.",
  "isImportant": true,
  "createdAt": "2026-05-20T05:00:00Z"
}
```

### Payload 4: Admissions Data Harvesting (Public Query Scrape)
An unauthenticated client attempts to scrape student contact logs by querying all submissions:
```
Operation: list /admissions
Condition: Filter is missing, or trying to fetch other students' private phone/email details.
```

### Payload 5: Memory Exhaustion via Notice Attachment Defacement
An attacker attempts to upload a 2MB base64 encoded text blob as the notice title to cause Denial of Wallet:
```json
// Path: /notices/exhaust_title
{
  "id": "exhaust_title",
  "title": "A [Repeated 500,000 times to create a massive string to inflate read costs] ...",
  "date": "May 20, 2026",
  "category": "admission",
  "content": "Short description",
  "createdAt": "2026-05-20T05:00:00Z"
}
```

### Payload 6: Admission Application Tampering (Anonymously Approved Status)
A user attempts to submit a pre-approved application directly with state `status: "approved"` to bypass administrative vetting:
```json
// Path: /admissions/application_cheat
{
  "id": "application_cheat",
  "fullName": "Imposter Student",
  "email": "imposter@gmail.com",
  "phone": "+977-9800000000",
  "program": "Science",
  "previousExam": "SEE",
  "gpa": "1.02",
  "status": "approved", // Injection of approved state
  "appliedDate": "2026-05-20",
  "createdAt": "2026-05-20T05:00:00Z"
}
```

### Payload 7: Static Resource Corruption (About Image Array Defacement)
A student attempts to edit the about images list to point to malicious media scripts:
```json
// Path: /site_settings/about
{
  "id": "about",
  "content": {
    "aboutText": "Valid text with valid content.",
    "sectionImages": ["https://malicious-executable-redirect.png"]
  },
  "updatedAt": "2026-05-20T05:00:00Z"
}
```

### Payload 8: SEO Poisoning
An attacker attempts to overwrite the sitemap settings to insert span redirection links:
```json
// Path: /site_settings/seo
{
  "id": "seo",
  "content": {
    "metaTitle": "Cheap Pharmaceutical Meds Free Online",
    "metaDescription": "Redirecting search indices now.",
    "keywords": "pharma, redirects",
    "openGraphImage": "https://malicious-og.png"
  },
  "updatedAt": "2026-05-20T05:00:00Z"
}
```

### Payload 9: Unauthorized Ad Insertion
An attacker attempts to inject their own fraudulent AdSense/tracking client ID through the Site Settings:
```json
// Path: /site_settings/ads
{
  "id": "ads",
  "content": {
    "adsenseCode": "<script src='https://malicious-adsense-hijack.js'></script>",
    "placement": "header",
    "isEnabled": true
  },
  "updatedAt": "2026-05-20T05:00:00Z"
}
```

### Payload 10: State Lock Bypass
An administrative user attempts to change the `appliedDate` or `email` of a completed or historical `AdmissionApplication` instead of only updating the `status` field:
```json
// Path: /admissions/historical_001
{
  "id": "historical_001",
  "fullName": "Original Student Name",
  "email": "hacked_email_injection@gmail.com", // Modifying email of a historical application is forbidden
  "phone": "+977-1234",
  "program": "Science",
  "previousExam": "SEE",
  "gpa": "3.90",
  "status": "under_review",
  "appliedDate": "2026-05-01",
  "createdAt": "2026-05-01T00:00:00Z"
}
```

### Payload 11: Rating Limit Hijack (5+ Star Injection)
An attacker tries to post a fake student testimonial with a rating score of 25:
```json
// Path: /testimonials/fake_rating_99
{
  "id": "fake_rating_99",
  "name": "Super Happy Student",
  "role": "Student",
  "content": "Perfect college!",
  "image": "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde",
  "rating": 25, // Score must be 1 to 5 only
  "createdAt": "2026-05-20T05:00:00Z"
}
```

### Payload 12: Orphaned Relationship Injection
An attacker registers an achievement statistic counter with zero or empty title to waste processing capacity:
```json
// Path: /stats/empty_stat
{
  "id": "empty_stat",
  "label": "", // Empty label causes visual clutter
  "value": -4000,
  "suffix": "---",
  "icon": "TrashCan",
  "createdAt": "2026-05-20T05:00:00Z"
}
```

---

## 3. The Security Assertion Test Runner Config

The following simulation tests verify total system locking in the environment:

```typescript
// firestore.rules.test.ts
import { assertFails, assertSucceeds, initializeTestEnvironment } from "@firebase/rules-unit-testing";

describe("College CMS Firewall Matrix", () => {
  let testEnv;

  before(async () => {
    testEnv = await initializeTestEnvironment({
      projectId: "gen-lang-client-0155146132",
      firestore: {
        rules: require("fs").readFileSync("firestore.rules", "utf8"),
      }
    });
  });

  after(async () => {
    await testEnv.cleanup();
  });

  it("should fail self-privilege escalation (Payload 1)", async () => {
    const context = testEnv.unauthenticatedContext();
    const db = context.firestore();
    await assertFails(
      db.doc("/admins/unauthorized_user_123").set({
        email: "malicious_attacker@gmail.com",
        uid: "unauthorized_user_123",
        createdAt: new Date()
      })
    );
  });

  it("should successfully allow initial admin bootstrap if email is awalelian22@gmail.com (Pillar 3/Pillar 6)", async () => {
    const context = testEnv.authenticatedContext("admin_uid_001", {
      email: "awalelian22@gmail.com"
    });
    const db = context.firestore();
    await assertSucceeds(
      db.doc("/admins/admin_uid_001").set({
        email: "awalelian22@gmail.com",
        uid: "admin_uid_001",
        createdAt: new Date()
      })
    );
  });
});
```
