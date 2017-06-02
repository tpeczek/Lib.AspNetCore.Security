# Violation Reports

Lib.AspNetCore.Security provides middlewares which can receive violation reports for following security headers:

- Content-Security-Policy ([`ContentSecurityPolicyReportingMiddleware`](../api/Lib.AspNetCore.Security.ContentSecurityPolicyReportingMiddleware.html))
- Expect-CT ([`ExpectCtReportingMiddleware`](../api/Lib.AspNetCore.Security.ExpectCtReportingMiddleware.html))

The middlewares can be added to the pipeline with `MapContentSecurityPolicyReporting` and `MapExpectCtReporting` extension methods.

```cs
public void Configure(IApplicationBuilder app)
{
    ...

    app.UseSecurityHeaders(builder =>
    {
        builder.WithCsp(
            ...
            reportUri: "/report-csp"
        )
        .WithReportOnlyExpectCt("https://example.com/report-ct")
        ...;
    })
    .MapContentSecurityPolicyReporting("/report-csp")
    .MapExpectCtReporting("/report-ct");

    ...
}
```

Underneath the covers the middlewares will look for [`ISecurityHeadersReportingService`](../api/Lib.AspNetCore.Security.ISecurityHeadersReportingService.html) service implementation, which might look like this:

```cs
public class LoggerSecurityHeadersReportingService : ISecurityHeadersReportingService
{
    private readonly ILogger _logger;

    public LoggerSecurityHeadersReportingService(ILogger<ISecurityHeadersReportingService> logger)
    {
        _logger = logger;
    }

    public Task OnContentSecurityPolicyViolationAsync(ContentSecurityPolicyViolationReport report)
    {
        _logger.LogWarning("Content Security Policy Violation: Document: {DocumentUri} | Resource: {BlockedUri} | Directive: {ViolatedDirective} | Disposition: {Disposition}",
            report.DocumentUri,
            report.BlockedUri,
            report.ViolatedDirective,
            report.Disposition);

        return Task.FromResult(0);
    }

    public Task OnExpectCtViolationAsync(ExpectCtViolationReport report)
    {
        _logger.LogWarning("Expect-CT Violation: Failure Date: {FailureDate} UTC | Effective Expiration Date: {EffectiveExpirationDate} UTC | Host: {Host} | Port: {Port}",
            report.FailureDate.ToUniversalTime(),
            report.EffectiveExpirationDate.ToUniversalTime(),
            report.Hostname,
            report.Port);

        return Task.FromResult(0);
    }
}
```

Service must be registered in the services collection during configuration, for example:

```cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddTransient<ISecurityHeadersReportingService, LoggerSecurityHeadersReportingService>();
    ...
}
```