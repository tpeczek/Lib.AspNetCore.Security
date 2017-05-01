using System;
using Lib.AspNetCore.Security;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// The <see cref="IApplicationBuilder"/> extensions for adding security middlewares support.
    /// </summary>
    public static class SecurityMiddlewareExtensions
    {
        #region Methods
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
