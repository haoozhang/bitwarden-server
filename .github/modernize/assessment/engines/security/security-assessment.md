# Security Assessment Report

**Generated:** 2026-06-22 07:48:07 UTC

## Summary

| Metric | Count |
|--------|-------|
| Total Findings | 14 |
| CVE Vulnerabilities | 4 |
| CWE Vulnerabilities | 10 |
| Total Rules Assessed | 59 |
| Rules Passed | 49 |

### By Severity

| Severity | Count |
|----------|-------|
| mandatory | 5 |
| optional | 4 |
| potential | 5 |

## CVE Findings (Dependency Vulnerabilities)
### CVE-2025-6965: SQLitePCLRaw.lib.e_sqlite3 has a vulnerable dependency on SQLite
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** src/Infrastructure.EntityFramework/Infrastructure.EntityFramework.csproj:14

[CVE-2025-6965](https://github.com/advisories/GHSA-2m69-gcr7-jv3q): SQLitePCLRaw.lib.e_sqlite3 has a vulnerable dependency on SQLite

Severity: HIGH

Affected dependencies:
  - SQLitePCLRaw.lib.e_sqlite3:2.1.6 (transitive, pulled by Microsoft.EntityFrameworkCore.Sqlite at src/Infrastructure.EntityFramework/Infrastructure.EntityFramework.csproj:14)

Recommended fix:
  - No patched version of SQLitePCLRaw.lib.e_sqlite3 is currently available. Monitor upstream for an update beyond 2.1.11.
### CVE-2026-32933: AutoMapper Vulnerable to Denial of Service (DoS) via Uncontrolled Recursion
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** src/Infrastructure.EntityFramework/Infrastructure.EntityFramework.csproj:9, bitwarden_license/src/Commercial.Infrastructure.EntityFramework/Commercial.Infrastructure.EntityFramework.csproj:7

[CVE-2026-32933](https://github.com/advisories/GHSA-rvv3-g6hj-g44x): AutoMapper Vulnerable to Denial of Service (DoS) via Uncontrolled Recursion

Severity: HIGH

Affected dependencies:
  - AutoMapper:14.0.0 (declared at src/Infrastructure.EntityFramework/Infrastructure.EntityFramework.csproj:9)
  - AutoMapper:14.0.0 (declared at bitwarden_license/src/Commercial.Infrastructure.EntityFramework/Commercial.Infrastructure.EntityFramework.csproj:7)

Note: This advisory is suppressed via NuGetAuditSuppress in Infrastructure.EntityFramework.csproj.

Recommended fix:
  - Upgrade AutoMapper to 15.1.1 or later.
### CVE-2026-45591: Microsoft Security Advisory CVE-2026-45591 - ASP.NET Core Denial of Service Vulnerability
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** src/Notifications/Notifications.csproj:11

[CVE-2026-45591](https://github.com/advisories/GHSA-f8h2-vmm9-qhj6): Microsoft Security Advisory CVE-2026-45591 - ASP.NET Core Denial of Service Vulnerability

Severity: HIGH

Affected dependencies:
  - Microsoft.AspNetCore.SignalR.Protocols.MessagePack:10.0.8 (declared at src/Notifications/Notifications.csproj:11)

Recommended fix:
  - Upgrade Microsoft.AspNetCore.SignalR.Protocols.MessagePack to 10.0.9 or later.
### CVE-2026-48109: MessagePack's LZ4 decompression may fail with AccessViolationException after dereferencing memory from bad input
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** AppHost/AppHost.csproj:17

[CVE-2026-48109](https://github.com/advisories/GHSA-hv8m-jj95-wg3x): MessagePack's LZ4 decompression may fail with AccessViolationException after dereferencing memory from bad input

Severity: HIGH

Affected dependencies:
  - MessagePack:2.5.192 (transitive, pulled by Aspire.Hosting.AppHost at AppHost/AppHost.csproj:17)

Recommended fix:
  - Upgrade MessagePack to 2.5.301 or later (or 3.1.7+ for the v3 series).

## CWE Findings (Code-Level Vulnerabilities)

### CWE-477: Use of Obsolete Function
- **Category:** Code Quality
- **Severity:** optional
- **Story Points:** 1
- **Files:** src/Api/Controllers/SelfHosted/SelfHostedOrganizationLicensesController.cs:131, src/Admin/Models/UserEditModel.cs:51, src/Admin/AdminConsole/Models/OrganizationEditModel.cs:123, src/Core/Auth/UserFeatures/TwoFactorAuth/Implementations/CompleteTwoFactorWebAuthnRegistrationCommand.cs:74, src/Api/Dirt/Controllers/HibpController.cs:31

Multiple instances of DateTime.Now (which returns local time) used instead of DateTimeOffset.UtcNow (e.g., SelfHostedOrganizationLicensesController.cs:131, UserEditModel.cs:51, OrganizationEditModel.cs:123, CompleteTwoFactorWebAuthnRegistrationCommand.cs:74). Additionally, HibpController.cs:31 directly instantiates HttpClient via 'new HttpClient()' in a static constructor rather than using IHttpClientFactory, an obsolete/discouraged pattern in modern .NET.
### CWE-681: Incorrect Conversion between Numeric Types
- **Category:** Code Quality
- **Severity:** potential
- **Story Points:** 3
- **Files:** bitwarden_license/src/Sso/Utilities/Saml2OptionsExtensions.cs:69

At line 69, MemoryStream.Length (a long) is cast to int without bounds checking: '(int)deCompressed.Length'. If a decompressed SAML payload exceeds Int32.MaxValue (~2GB), this unchecked narrowing cast would silently overflow, causing incorrect string length extraction from a user-controlled SAML request/response.
### CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime
- **Category:** Code Quality
- **Severity:** potential
- **Story Points:** 3
- **Files:** src/Core/Utilities/SystemTextJsonCosmosSerializer.cs:38

At line 38, a MemoryStream is created without a 'using' statement and is returned to the caller from ToStream<T>(). The caller (Cosmos SDK) is expected to dispose it, but no contract enforces this, creating a potential resource leak if the SDK does not properly dispose the returned stream.
### CWE-543: Use of Singleton Pattern Without Synchronization in a Multithreaded Context
- **Category:** Concurrency & Synchronization
- **Severity:** potential
- **Story Points:** 5
- **Files:** src/Core/Platform/Push/NotificationHub/NotificationHubConnection.cs:32

The HubClient property getter at lines 32-46 implements a lazy-initialization singleton pattern without synchronization. It checks 'if (_hubClient == null)' and then calls Init() without any lock. In a multithreaded ASP.NET Core environment, concurrent requests could observe _hubClient as null simultaneously, causing multiple calls to NotificationHubClient.CreateClientFromConnectionString(), creating duplicate clients. The field is also not marked volatile, so visibility guarantees are absent.
### CWE-567: Unsynchronized Access to Shared Data in a Multithreaded Context
- **Category:** Concurrency & Synchronization
- **Severity:** potential
- **Story Points:** 5
- **Files:** src/Api/Dirt/Controllers/HibpController.cs:22

HibpController declares 'private static HttpClient _httpClient' (line 22) as a non-readonly mutable static field. While it is only written once in the static constructor, it is not marked as readonly or volatile. Static mutable fields shared across requests without synchronization can cause issues in highly concurrent scenarios if the field were ever reassigned.
### CWE-778: Insufficient Logging
- **Category:** Credentials & Secrets
- **Severity:** potential
- **Story Points:** 3
- **Files:** src/Core/Services/Implementations/UserService.cs:282

At lines 282-283 in UserService.DeleteUserAsync, GatewayException and BillingException are silently caught and discarded with empty catch blocks during user account deletion. Billing errors in a security-critical operation (account deletion) are not logged, making it impossible to audit or investigate billing-related failures during user removal.
### CWE-434: Unrestricted Upload of File with Dangerous Type
- **Category:** File & Path Security
- **Severity:** mandatory
- **Story Points:** 8
- **Files:** src/Api/Vault/Controllers/CiphersController.cs:1316, src/Api/Vault/Controllers/CiphersController.cs:1385

The cipher attachment upload endpoints (PostAttachment at line 1316 and PostFileForExistingAttachment at line 1385 in CiphersController.cs) accept file uploads without validating the file type or content type. Only file size is enforced (MAX_FILE_SIZE). No MIME type whitelist or file extension restrictions are applied, allowing any file type to be uploaded.
### CWE-611: Improper Restriction of XML External Entity Reference
- **Category:** File & Path Security
- **Severity:** optional
- **Story Points:** 5
- **Files:** bitwarden_license/src/Sso/Utilities/Saml2OptionsExtensions.cs:53

XmlHelpers.XmlDocumentFromString() from the Sustainsys.Saml2 library is called at lines 53 and 68 to parse user-controlled SAML XML responses. No explicit DTD disabling or external entity restrictions are set in the Bitwarden code itself. The safety depends entirely on the Sustainsys.Saml2 library's internal implementation.
### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **Category:** Injection Attacks
- **Severity:** optional
- **Story Points:** 8
- **Files:** bitwarden_license/src/Sso/Views/Shared/Error.cshtml:10

At line 10 of Error.cshtml, the user-controlled SSO redirect URI (Model?.RedirectUri) is embedded in a translated string via i18nService.T() and then rendered without encoding using @Html.Raw(). If the redirect URI contains HTML special characters or script tags, this results in a reflected XSS vulnerability in the SSO error page.
### CWE-91: XML Injection (aka Blind XPath Injection)
- **Category:** Injection Attacks
- **Severity:** optional
- **Story Points:** 5
- **Files:** bitwarden_license/src/Sso/Utilities/Saml2OptionsExtensions.cs:53

At lines 53 and 68, XmlHelpers.XmlDocumentFromString() from the Sustainsys.Saml2 library is used to parse SAML request/response XML that originates from user-controlled HTTP parameters (SAMLRequest/SAMLResponse). No explicit XML neutralization is applied in the Bitwarden code before parsing, relying entirely on the Sustainsys library's protections.
