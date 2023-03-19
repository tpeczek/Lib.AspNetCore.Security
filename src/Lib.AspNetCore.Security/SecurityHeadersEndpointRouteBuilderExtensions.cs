#if !NETSTANDARD2_0
using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Lib.AspNetCore.Security;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Provides extension methods for <see cref="IEndpointRouteBuilder"/> to add security endpoints.
    /// </summary>
    public static class SecurityHeadersEndpointRouteBuilderExtensions
    {
        #region Fields
        private const string CONTENT_SECURITY_POLICY_REPORTING_DISPLAY_NAME = "Content-Security-Policy Reporting";
        private const string EXPECT_CT_REPORTING_DISPLAY_NAME = "Expect-CT Reporting";
        private const string TARGETED_SITE_DATA_CLEARING_DISPLAY_NAME = "Targeted Site Data Clearing";
        #endregion

        #region Methods
        /// <summary>
        /// Adds an Content-Security-Policy and Content-Security-Policy-Report-Only violation reports endpoint to the <see cref="IEndpointRouteBuilder"/> with the specified template.
        /// </summary>
        /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the Content-Security-Policy and Content-Security-Policy-Report-Only violation reports endpoint to.</param>
        /// <param name="pattern">The URL pattern of the Content-Security-Policy and Content-Security-Policy-Report-Only violation reports endpoint.</param>
        /// <returns>A convention routes for the Content-Security-Policy and Content-Security-Policy-Report-Only violation reports endpoint.</returns>
        public static IEndpointConventionBuilder MapContentSecurityPolicyReporting(this IEndpointRouteBuilder endpoints, string pattern)
        {
            if (endpoints == null)
            {
                throw new ArgumentNullException(nameof(endpoints));
            }

            RequestDelegate pipeline = endpoints.CreateApplicationBuilder()
                .UseMiddleware<ContentSecurityPolicyReportingMiddleware>()
               .Build();

            return endpoints.Map(pattern, pipeline).WithDisplayName(CONTENT_SECURITY_POLICY_REPORTING_DISPLAY_NAME);
        }

        /// <summary>
        /// Adds an Expect-CT violation reports endpoint to the <see cref="IEndpointRouteBuilder"/> with the specified template.
        /// </summary>
        /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the Expect-CT violation reports endpoint to.</param>
        /// <param name="pattern">The URL pattern of the Expect-CT violation reports endpoint.</param>
        /// <returns>A convention routes for the Expect-CT violation reports endpoint.</returns>
        public static IEndpointConventionBuilder MapExpectCtReporting(this IEndpointRouteBuilder endpoints, string pattern)
        {
            if (endpoints == null)
            {
                throw new ArgumentNullException(nameof(endpoints));
            }

            RequestDelegate pipeline = endpoints.CreateApplicationBuilder()
                .UseMiddleware<ExpectCtReportingMiddleware>()
               .Build();

            return endpoints.Map(pattern, pipeline).WithDisplayName(EXPECT_CT_REPORTING_DISPLAY_NAME);
        }

        /// <summary>
        /// Adds a targeted site data clearing endpoint to the <see cref="IEndpointRouteBuilder"/> with the specified template.
        /// </summary>
        /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the targeted site data clearing endpoint to.</param>
        /// <param name="pattern">The URL pattern of the targeted site data clearing endpoint.</param>
        /// <returns>A convention routes for the targeted site data clearing endpoint.</returns>
        public static IEndpointConventionBuilder MapTargetedSiteDataClearing(this IEndpointRouteBuilder endpoints, string pattern)
        {
            if (endpoints == null)
            {
                throw new ArgumentNullException(nameof(endpoints));
            }

            RequestDelegate pipeline = endpoints.CreateApplicationBuilder()
                .UseMiddleware<TargetedSiteDataClearingMiddleware>()
               .Build();

            return endpoints.Map(pattern, pipeline).WithDisplayName(TARGETED_SITE_DATA_CLEARING_DISPLAY_NAME);
        }

        /// <summary>
        /// Adds a targeted site data clearing endpoint to the <see cref="IEndpointRouteBuilder"/> with the specified template and options.
        /// </summary>
        /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to add the targeted site data clearing endpoint to.</param>
        /// <param name="pattern">The URL pattern of the targeted site data clearing endpoint.</param>
        /// <param name="options">An instance of the <see cref="TargetedSiteDataClearingOptions"/> to configure the endpoint.</param>
        /// <returns>A convention routes for the targeted site data clearing endpoint.</returns>
        public static IEndpointConventionBuilder MapTargetedSiteDataClearing(this IEndpointRouteBuilder endpoints, string pattern, TargetedSiteDataClearingOptions options)
        {
            if (endpoints == null)
            {
                throw new ArgumentNullException(nameof(endpoints));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            RequestDelegate pipeline = endpoints.CreateApplicationBuilder()
                .UseMiddleware<TargetedSiteDataClearingMiddleware>(Options.Create(options))
               .Build();

            return endpoints.Map(pattern, pipeline).WithDisplayName(TARGETED_SITE_DATA_CLEARING_DISPLAY_NAME);
        }
        #endregion
    }
}
#endif
