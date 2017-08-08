## Lib.AspNetCore.Security 2.3.0
### Additions and Changes
- Added support for Feature-Policy through `SecurityHeadersMiddleware`, `SingleFeaturePolicyHeaderValue` and `MultipleFeaturePolicyHeaderValue`

## Lib.AspNetCore.Security 2.2.0 and Lib.AspNetCore.Mvc.Security 2.2.0
### Additions and Changes
- Added support for X-Permitted-Cross-Domain-Policies through `SecurityHeadersMiddleware` and `XPermittedCrossDomainPoliciesHeaderValue`
- Added support for SHA-384 and SHA-512 hashes in Content Security Policy
- Added `ContentSecurityPolicySourceListBuilder` which provides methods for building Content Security Policy source list

## Lib.AspNetCore.Security 2.1.0 and Lib.AspNetCore.Mvc.Security 2.1.0
### Bug Fixes
- Adjusted nonce generation to specification
### Additions and Changes
- Added support for Referrer-Policy through `SecurityHeadersMiddleware` and `ReferrerPolicyHeaderValue`
- Added support for X-Frame-Options through `SecurityHeadersMiddleware`, `XFrameOptionsAttribute` and `XFrameOptionsHeaderValue`
- Added support for X-XSS-Protection through `SecurityHeadersMiddleware`, `XXssProtectionAttribute` and `XXssProtectionHeaderValue`
- Added support for X-Content-Type-Options through `SecurityHeadersMiddleware`
- Added support for X-Download-Options through `SecurityHeadersMiddleware`
- Added support for block-all-mixed-content directive in Content Security Policy
- Added support for upgrade-insecure-requests directive in Content Security Policy
- Added support for require-sri-for directive in Content Security Policy
- Added support for plugin-types directive in Content Security Policy
- Added support for worker-src directive in Content Security Policy
- Added support for frame-src directive in Content Security Policy
- Added support for Content Security Policy reporting through `ISecurityHeadersReportingService`, `ContentSecurityPolicyReportingMiddleware` and `ContentSecurityPolicyViolationReport`
- Added support for hashes caching in Content Security Policy tag helper
- Added `HttpResponseHeadersExtensions` which provides methods for directly setting headers on response

## Lib.AspNetCore.Security 2.0.0 and Lib.AspNetCore.Mvc.Security 2.0.0
### Additions and Changes
- Introduced Lib.AspNetCore.Security with `SecurityHeadersMiddleware` to centralize security headers support. Initial support includes HSTS, CSP and Expect-CT
- Removed `RequireHstsAttribute` as HSTS support is now provided by `SecurityHeadersMiddleware`
- Removed `ContentSecurityPolicyAttribute` as CSP support is now provided by `SecurityHeadersMiddleware` (CSP tag helper and html helper now depend on `SecurityHeadersMiddleware`)
- Added `ExpectCtReportingMiddleware`, `ExpectCtViolationReport` and `ISecurityHeadersReportingService` for supporting Expect-CT violation reports
- Added `ContentSecurityPolicyHeaderValue`, `StrictTransportSecurityHeaderValue` and `ExpectCtHeaderValue` for low level headers support

## Lib.AspNetCore.Mvc.Security 1.1.0
### Additions and Changes
- Added Tag Helper for Content Security Policy support

## Lib.AspNetCore.Mvc.Security 1.0.0
### Initial functionality
- Filter attribute and `HtmlHelper` extensions for Content Security Policy support
- Filter attribute for Strict Transport Security support