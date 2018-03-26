# Clear Site Data

Lib.AspNetCore.Security provides support for [clearing site data](http://www.w3.org/TR/clear-site-data/). Beside [header value class](../api/Lib.AspNetCore.Security.Http.Headers.ClearSiteDataHeaderValue.html) and [HttpResponse extensions](../api/Lib.AspNetCore.Security.Http.Extensions.HttpResponseHeadersExtensions.html), there are additional components for supporting two main uses cases.

## Signing Out

When user signs out from application, and you want to ensure that locally stored data is removed as a result, you can register a service which will attach clear site data functionality to ASP.NET Core built-in sign out. The registration needs to be done after registering the built-in authentication services.

```cs
public void ConfigureServices(IServiceCollection services)
{
	...

    services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);

	...

    services.AddClearSiteDataAuthentication(new ClearSiteDataHeaderValue
    {
        ClearCache = true,
        ClearCookies = true,
        ClearStorage = true,
        ClearExecutionContexts = true
    });
    
	...
}
```

## Targeted Clearing

If your application is configured under a subdomain (or you are handling subdomains internally), you may want to expose and endpoint which will allow the "master" application to clear data for specific subdomain. Lib.AspNetCore.Security provides [`TargetedSiteDataClearingMiddleware`](../api/Lib.AspNetCore.Security.TargetedSiteDataClearingMiddleware.html) which allows for doing exactly that.

```cs
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
	...

	app.MapTargetedSiteDataClearing("/clear-site-data", new TargetedSiteDataClearingOptions
    {
        ValidateAntiforgery = true,
        ClearCache = true,
        ClearCookies = true,
        ClearStorage = true,
        ClearExecutionContexts = true
    });

	...
}

```

The middleware behaviour can be controlled through [`TargetedSiteDataClearingOptions`](../api/Lib.AspNetCore.Security.TargetedSiteDataClearingOptions.html).