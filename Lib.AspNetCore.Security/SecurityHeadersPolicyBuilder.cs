using System;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Exposes methods to build a <see cref="SecurityHeadersPolicy"/>.
    /// </summary>
    public class SecurityHeadersPolicyBuilder
    {
        #region Fields
        private readonly SecurityHeadersPolicy _policy = new SecurityHeadersPolicy();
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="SecurityHeadersPolicyBuilder"/>.
        /// </summary>
        public SecurityHeadersPolicyBuilder()
        { }
        #endregion

        #region Methods
        /// <summary>
        /// Adds the Content Security Policy to the policy.
        /// </summary>
        /// <param name="baseUri">The list of URLs that can be used to specify the document base URL.</param>
        /// <param name="childSources">The source list for web workers and nested browsing contexts.</param>
        /// <param name="connectSources">The source list for fetch, XMLHttpRequest, WebSocket, and EventSource connections.</param>
        /// <param name="defaultSources">The default source list for directives which can fall back to the default sources.</param>
        /// <param name="fontSources">The source list for fonts loaded using @font-face.</param>
        /// <param name="formAction">The valid endpoints for form submissions.</param>
        /// <param name="frameAncestorsSources">The valid parents that may embed a page using the frame and iframe elements.</param>
        /// <param name="imageSources">The source list for of images and favicons.</param>
        /// <param name="manifestSources">The source list for manifest which can be applied to the resource.</param>
        /// <param name="mediaSources">The source list for loading media using the audio and video elements.</param>
        /// <param name="objectSources">The source list for the object, embed, and applet elements.</param>
        /// <param name="reportUri">The URL to which the user agent should send reports about policy violations.</param>
        /// <param name="sandbox">The value indicating if sandbox policy should be applied.</param>
        /// <param name="sandboxFlags">The sandboxing flags (only used when Sandbox is true).</param>
        /// <param name="scriptSources">The source list for scripts.</param>
        /// <param name="scriptInlineExecution">The inline execution mode for scripts.</param>
        /// <param name="styleSources">The source list for stylesheets.</param>
        /// <param name="styleInlineExecution">The inline execution mode for stylesheets.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithCsp(string baseUri = null, string childSources = null, string connectSources = null,
            string defaultSources = ContentSecurityPolicyHeaderValue.NoneSource, string fontSources = null, string formAction = null, string frameAncestorsSources = null, string imageSources = null,
            string manifestSources = null, string mediaSources = null, string objectSources = null, string reportUri = null,
            bool sandbox = false, ContentSecurityPolicySandboxFlags sandboxFlags = ContentSecurityPolicySandboxFlags.None,
            string scriptSources = null, ContentSecurityPolicyInlineExecution scriptInlineExecution = ContentSecurityPolicyInlineExecution.Refuse, string styleSources = null, ContentSecurityPolicyInlineExecution styleInlineExecution = ContentSecurityPolicyInlineExecution.Refuse)
        {
            return WithCsp(false, baseUri, childSources, connectSources, defaultSources, fontSources, formAction, frameAncestorsSources,
                imageSources, manifestSources, mediaSources, objectSources, reportUri, sandbox, sandboxFlags,
                scriptSources, scriptInlineExecution, styleSources, styleInlineExecution);
        }

        /// <summary>
        /// Adds the report only Content Security Policy to the policy.
        /// </summary>
        /// <param name="baseUri">The list of URLs that can be used to specify the document base URL.</param>
        /// <param name="childSources">The source list for web workers and nested browsing contexts.</param>
        /// <param name="connectSources">The source list for fetch, XMLHttpRequest, WebSocket, and EventSource connections.</param>
        /// <param name="defaultSources">The default source list for directives which can fall back to the default sources.</param>
        /// <param name="fontSources">The source list for fonts loaded using @font-face.</param>
        /// <param name="formAction">The valid endpoints for form submissions.</param>
        /// <param name="frameAncestorsSources">The valid parents that may embed a page using the frame and iframe elements.</param>
        /// <param name="imageSources">The source list for of images and favicons.</param>
        /// <param name="manifestSources">The source list for manifest which can be applied to the resource.</param>
        /// <param name="mediaSources">The source list for loading media using the audio and video elements.</param>
        /// <param name="objectSources">The source list for the object, embed, and applet elements.</param>
        /// <param name="reportUri">The URL to which the user agent should send reports about policy violations.</param>
        /// <param name="sandbox">The value indicating if sandbox policy should be applied.</param>
        /// <param name="sandboxFlags">The sandboxing flags (only used when Sandbox is true).</param>
        /// <param name="scriptSources">The source list for scripts.</param>
        /// <param name="scriptInlineExecution">The inline execution mode for scripts.</param>
        /// <param name="styleSources">The source list for stylesheets.</param>
        /// <param name="styleInlineExecution">The inline execution mode for stylesheets.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithReportOnlyCsp(string baseUri = null, string childSources = null, string connectSources = null,
            string defaultSources = ContentSecurityPolicyHeaderValue.NoneSource, string fontSources = null, string formAction = null, string frameAncestorsSources = null, string imageSources = null,
            string manifestSources = null, string mediaSources = null, string objectSources = null, string reportUri = null,
            bool sandbox = false, ContentSecurityPolicySandboxFlags sandboxFlags = ContentSecurityPolicySandboxFlags.None,
            string scriptSources = null, ContentSecurityPolicyInlineExecution scriptInlineExecution = ContentSecurityPolicyInlineExecution.Refuse, string styleSources = null, ContentSecurityPolicyInlineExecution styleInlineExecution = ContentSecurityPolicyInlineExecution.Refuse)
        {
            return WithCsp(true, baseUri, childSources, connectSources, defaultSources, fontSources, formAction, frameAncestorsSources,
                imageSources, manifestSources, mediaSources, objectSources, reportUri, sandbox, sandboxFlags,
                scriptSources, scriptInlineExecution, styleSources, styleInlineExecution);
        }

        /// <summary>
        /// Adds the Expect-CT to the policy.
        /// </summary>
        /// <param name="maxAge">The number of seconds after the reception of the Expect-CT header field during which the client should regard the host from whom the message was received as a Known Expect-CT Host.</param>
        /// <param name="enforce">The value indicating if compliance to the CT Policy should be enforced.</param>
        /// <param name="reportUri">The absolute URI to which the client should report Expect-CT failures.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithExpectCt(uint maxAge = ExpectCtHeaderValue.DefauMaxAge, bool enforce = false, string reportUri = null)
        {
            _policy.ExpectCt = new ExpectCtHeaderValue(maxAge)
            {
                Enforce = enforce,
                ReportUri = reportUri
            };

            return this;
        }

        /// <summary>
        /// Adds the report only Expect-CT to the policy.
        /// </summary>
        /// <param name="reportUri">The absolute URI to which the client should report Expect-CT failures.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithReportOnlyExpectCt(string reportUri)
        {
            return WithExpectCt(ExpectCtHeaderValue.ReportOnlyMaxAge, false, reportUri);
        }

        /// <summary>
        /// Adds the HTTP Strict Transport Security to the policy.
        /// </summary>
        /// <param name="maxAge">The time (in seconds) that the browser should remember that this resource is only to be accessed using HTTPS.</param>
        /// <param name="includeSubDomains">Tthe value indicating if this rule applies to all subdomains as well.</param>
        /// <param name="preload">The value indicating if subscription to HSTS preload list should be confirmed.</param>
        /// <param name="sslPort">The SSL port used by application.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithHsts(uint maxAge, bool includeSubDomains = false, bool preload = false, int? sslPort = null)
        {
            _policy.Hsts = new StrictTransportSecurityHeaderValue(maxAge)
            {
                IncludeSubDomains = includeSubDomains,
                Preload = preload
            };
            _policy.SslPort = sslPort;

            return this;
        }

        /// <summary>
        /// Adds the Referrer-Policy.
        /// </summary>
        /// <param name="directive">The directive.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithReferrerPolicy(ReferrerPolicyDirectives directive)
        {
            _policy.ReferrerPolicy = new ReferrerPolicyHeaderValue(directive);

            return this;
        }

        /// <summary>
        /// Adds the X-Content-Type-Options.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithXContentTypeOptions()
        {
            _policy.XContentTypeOptions = true;

            return this;
        }

        /// <summary>
        /// Adds the X-Download-Options.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithXDownloadOptions()
        {
            _policy.XDownloadOptions = true;

            return this;
        }

        /// <summary>
        /// Adds the X-Frame-Options with <see cref="XFrameOptionsDirectives.Deny"/> directive.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithDenyXFrameOptions()
        {
            return WithXFrameOptions(XFrameOptionsDirectives.Deny, null);
        }

        /// <summary>
        /// Adds the X-Frame-Options with <see cref="XFrameOptionsDirectives.SameOrigin"/> directive.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithSameOriginXFrameOptions()
        {
            return WithXFrameOptions(XFrameOptionsDirectives.SameOrigin, null);
        }

        /// <summary>
        /// Adds the X-Frame-Options with <see cref="XFrameOptionsDirectives.AllowFrom"/> directive.
        /// </summary>
        /// <param name="origin">The serialized origin.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithAllowFromXFrameOptions(string origin)
        {
            if (String.IsNullOrWhiteSpace(origin))
            {
                throw new ArgumentNullException(nameof(origin));
            }

            return WithXFrameOptions(XFrameOptionsDirectives.AllowFrom, origin);
        }

        /// <summary>
        /// Adds the X-XSS-Protection with <see cref="XssFilteringModes.None"/> mode.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithNoneXssFiltering()
        {
            return WithXssFiltering(XssFilteringModes.None);
        }

        /// <summary>
        /// Adds the X-XSS-Protection with <see cref="XssFilteringModes.Sanitize"/> mode.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithSanitizeXssFiltering()
        {
            return WithXssFiltering(XssFilteringModes.Sanitize);
        }

        /// <summary>
        /// Adds the X-XSS-Protection with <see cref="XssFilteringModes.Block"/> mode.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithBlockXssFiltering()
        {
            return WithXssFiltering(XssFilteringModes.Block);
        }

        /// <summary>
        /// Builds a new <see cref="SecurityHeadersPolicy"/> using the settings added.
        /// </summary>
        /// <returns>The constructed <see cref="SecurityHeadersPolicy"/>.</returns>
        public SecurityHeadersPolicy Build()
        {
            return _policy;
        }

        private SecurityHeadersPolicyBuilder WithCsp(bool reportOnly, string baseUri, string childSources, string connectSources,
            string defaultSources, string fontSources, string formAction, string frameAncestorsSources, string imageSources,
            string manifestSources, string mediaSources, string objectSources, string reportUri, bool sandbox, ContentSecurityPolicySandboxFlags sandboxFlags,
            string scriptSources, ContentSecurityPolicyInlineExecution scriptInlineExecution, string styleSources, ContentSecurityPolicyInlineExecution styleInlineExecution)
        {
            _policy.Csp = new ContentSecurityPolicyHeaderValue
            {
                BaseUri = baseUri,
                ChildSources = childSources,
                ConnectSources = connectSources,
                DefaultSources = defaultSources,
                FontSources = fontSources,
                FormAction = formAction,
                FrameAncestorsSources = frameAncestorsSources,
                ImageSources = imageSources,
                ManifestSources = manifestSources,
                MediaSources = mediaSources,
                ObjectSources = objectSources,
                ReportUri = reportUri,
                Sandbox = sandbox,
                SandboxFlags = sandboxFlags,
                ScriptSources = scriptSources,
                ScriptInlineExecution = scriptInlineExecution,
                StyleSources = styleSources,
                StyleInlineExecution = styleInlineExecution
            };
            _policy.IsCspReportOnly = reportOnly;

            return this;
        }

        private SecurityHeadersPolicyBuilder WithXFrameOptions(XFrameOptionsDirectives directive, string origin)
        {
            _policy.XFrameOptions = new XFrameOptionsHeaderValue(directive)
            {
                Origin = origin
            };

            return this;
        }

        private SecurityHeadersPolicyBuilder WithXssFiltering(XssFilteringModes mode)
        {
            _policy.XXssProtection = new XXssProtectionHeaderValue(mode);

            return this;
        }
        #endregion
    }
}
