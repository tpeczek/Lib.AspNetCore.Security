# Content Security Policy Tag Helpers

Lib.AspNetCore.Mvc.Security provides Tag Helpers  for `script` and `style` elements which can be used together with [`SecurityHeadersMiddleware`](../api/Lib.AspNetCore.Security.SecurityHeadersMiddleware.html) for genetaring nonce and digest (hash) sources for inline elements.

Configuration of [`SecurityHeadersMiddleware`](../api/Lib.AspNetCore.Security.SecurityHeadersMiddleware.html) is a required prerequisite as it injects [`IContentSecurityPolicyInlineExecutionFeature`](../api/Lib.AspNetCore.Security.Http.Features.IContentSecurityPolicyInlineExecutionFeature.html) which Tag Helpers rely on.

```cs
public void Configure(IApplicationBuilder app)
{
    ...

    app.UseSecurityHeaders(builder =>
    {
        builder.WithCsp(
            ...,
			scriptInlineExecution: ContentSecurityPolicyInlineExecution.Hash,
            styleInlineExecution: ContentSecurityPolicyInlineExecution.Hash
        )
        ...;
    });

    ...
}
```

The Tag Helpers target `csp-script` and `csp-style` elements, or `script` and `style` elements with `asp-csp` attribute.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    ...
    <style asp-csp="cache">
        ...
    </style>
</head>
<body>
    ...
    <script asp-csp>
        ...
    </script>
</body>
</html>
```

Depending on which option has been set for inline execution the Tag Helpers will either add the `nonce` attribute to the element or calculate the hash and add it to header value.

In case of hashes, if the content of element is static, there is an option of caching the calculated hash. In order to opt in for hash to be cached the `asp-csp` attribute value should be set to `cache`.

```html
<script asp-csp="cache">
    ...
</script>
```