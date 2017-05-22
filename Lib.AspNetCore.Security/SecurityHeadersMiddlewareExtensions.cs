using System;
using Microsoft.AspNetCore.Http;
using Lib.AspNetCore.Security;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// The <see cref="IApplicationBuilder"/> extensions for adding security middlewares support.
    /// </summary>
    public static class SecurityHeadersMiddlewareExtensions
    {
        #region Methods
        /// <summary>
        /// Adds the middleware which provides support for Content-Security-Policy and Content-Security-Policy-Report-Only violation reports.
        /// </summary>
        /// <param name="app">The pipeline builder.</param>
        /// <param name="pathMatch">The request path to match.</param>
        /// <returns>The pipeline builder.</returns>
        public static IApplicationBuilder MapContentSecurityPolicyReporting(this IApplicationBuilder app, PathString pathMatch)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.Map(pathMatch, branchedApp => branchedApp.UseMiddleware<ContentSecurityPolicyReportingMiddleware>());
        }

        /// <summary>
        /// Adds the middleware which provides support for Expect-CT violation reports.
        /// </summary>
        /// <param name="app">The pipeline builder.</param>
        /// <param name="pathMatch">The request path to match.</param>
        /// <returns>The pipeline builder.</returns>
        public static IApplicationBuilder MapExpectCtReporting(this IApplicationBuilder app, PathString pathMatch)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.Map(pathMatch, branchedApp => branchedApp.UseMiddleware<ExpectCtReportingMiddleware>());
        }

        /// <summary>
        /// Adds a <see cref="SecurityHeadersMiddleware"/> to application pipeline.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> passed to Configure method.</param>
        /// <param name="configurePolicy">A delegate which can use a <see cref="SecurityHeadersPolicyBuilder"/> to build a policy.</param>
        /// <returns>The original app parameter</returns>
        public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app, Action<SecurityHeadersPolicyBuilder> configurePolicy)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (configurePolicy == null)
            {
                throw new ArgumentNullException(nameof(configurePolicy));
            }

            SecurityHeadersPolicyBuilder policyBuilder = new SecurityHeadersPolicyBuilder();
            configurePolicy(policyBuilder);

            return app.UseMiddleware<SecurityHeadersMiddleware>(policyBuilder.Build());

        }
        #endregion
    }
}
