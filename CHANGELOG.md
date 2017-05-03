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