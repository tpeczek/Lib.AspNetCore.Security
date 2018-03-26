# Security Headers

The main functionality of Lib.AspNetCore.Security is support for security headers configuration. The support comes in three ways:

- [Header value classes](../api/Lib.AspNetCore.Security.Http.Headers.html)
- [HttpResponse extensions](../api/Lib.AspNetCore.Security.Http.Extensions.HttpResponseHeadersExtensions.html)
- [Middleware](../api/Lib.AspNetCore.Security.SecurityHeadersMiddleware.html)

Below table summarizes which options are available for specific headers.

Header | Header Value Class | HttpResponse Extension | Middleware
------ | ------------------ | ---------------------- | ----------
Clear-Site-Data | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.ClearSiteDataHeaderValue.html) | Yes | No
Content-Security-Policy*(-Report-Only)* | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.ContentSecurityPolicyHeaderValue.html) | No | Yes
Expect-CT | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.ExpectCtHeaderValue.html) | Yes | Yes
Feature-Policy | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.FeaturePolicyHeaderValue.html) | Yes | Yes
Referrer-Policy | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.ReferrerPolicyHeaderValue.html) | Yes | Yes
Strict-Transport-Security | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.StrictTransportSecurityHeaderValue.html) | Yes | Yes
X-Content-Type-Options | No | Yes | Yes
X-Download-Options | No | Yes | Yes
X-Frame-Options | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.XFrameOptionsHeaderValue.html) | Yes | Yes
X-Permitted-Cross-Domain-Policies | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.XPermittedCrossDomainPoliciesHeaderValue.html) | Yes | Yes
X-XSS-Protection | [Yes](../api/Lib.AspNetCore.Security.Http.Headers.XXssProtectionHeaderValue.html) | Yes | Yes


## Configuring security headers with middleware

To configure security headers for entire application add the [middleware](../api/Lib.AspNetCore.Security.SecurityHeadersMiddleware.html) to request pipeline using the `UseSecurityHeaders` extension method. Note that the middleware must precede any defined endpoints in application that are supposed to be protected (for example before call to `UseMvc`).

The security headers can be configured when adding the middleware using the [`SecurityHeadersPolicyBuilder`](../api/Lib.AspNetCore.Security.SecurityHeadersPolicyBuilder.html) class by calling `UseSecurityHeaders` with a lambda which takes a [`SecurityHeadersPolicyBuilder`](../api/Lib.AspNetCore.Security.SecurityHeadersPolicyBuilder.html) as parameter.

```cs
public void Configure(IApplicationBuilder app)
{
    ...

    app.UseSecurityHeaders(builder =>
    {
        builder.WithCsp(
            fontSources: "fonts.gstatic.com",
            imageSources: ContentSecurityPolicyHeaderValue.SelfSource,
            scriptSources: (new ContentSecurityPolicySourceListBuilder())
				.WithSelfKeyword()
				.WithUrls("cdnjs.cloudflare.com")
				.Build(),
            scriptInlineExecution: ContentSecurityPolicyInlineExecution.Hash,
            styleSources: (new ContentSecurityPolicySourceListBuilder())
				.WithSelfKeyword()
				.WithUrls("fonts.googleapis.com")
				.Build(),
            styleInlineExecution: ContentSecurityPolicyInlineExecution.Hash
        )
        .WithDenyXFrameOptions()
        .WithBlockXssFiltering()
        .WithXContentTypeOptions()
        .WithXDownloadOptions()
        .WithReferrerPolicy(ReferrerPolicyDirectives.NoReferrer)
		.WithNoneXPermittedCrossDomainPolicies()
		.WithFeaturePolicy(new FeaturePolicy
        {
            Camera = new[] { "https://other.com" },
            Microphone = new [] { "https://other.com" }
        });
    });

    ...
}
```

There is also an option for overriding some of the headers values when MVC is being used through [attributes](../api/Lib.AspNetCore.Mvc.Security.Filters.html) available in Lib.AspNetCore.Mvc.Security.