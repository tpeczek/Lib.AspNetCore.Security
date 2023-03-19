﻿using System;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// The names of HTTP headers
    /// </summary>
    public static class HeaderNames
    {
        /// <summary>
        /// The Clear-Site-Data header.
        /// </summary>
        public const string ClearSiteData = "Clear-Site-Data";

        /// <summary>
        /// The Content-Security-Policy header.
        /// </summary>
        public const string ContentSecurityPolicy = "Content-Security-Policy";

        /// <summary>
        /// The Content-Security-Policy-Report-Only header.
        /// </summary>
        public const string ContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only";

        /// <summary>
        /// The Expect-CT header.
        /// </summary>
        public const string ExpectCt = "Expect-CT";

        /// <summary>
        /// The Feature-Policy header.
        /// </summary>
        [Obsolete("Feature Policy has been replaced with Permissions Policy.")]
        public const string FeaturePolicy = "Feature-Policy";

        /// <summary>
        /// The Permissions-Policy header.
        /// </summary>
        public const string PermissionsPolicy = "Permissions-Policy";

        /// <summary>
        /// The Referrer-Policy header.
        /// </summary>
        public const string ReferrerPolicy = "Referrer-Policy";

        /// <summary>
        /// The Strict-Transport-Security header.
        /// </summary>
        public const string StrictTransportSecurity = "Strict-Transport-Security";

        /// <summary>
        /// The X-Content-Type-Options header.
        /// </summary>
        public const string XContentTypeOptions = "X-Content-Type-Options";

        /// <summary>
        /// The X-Download-Options header.
        /// </summary>
        public const string XDownloadOptions = "X-Download-Options";

        /// <summary>
        /// The X-Frame-Options header.
        /// </summary>
        public const string XFrameOptions = "X-Frame-Options";

        /// <summary>
        /// The X-Permitted-Cross-Domain-Policies header.
        /// </summary>
        public const string XPermittedCrossDomainPolicies = "X-Permitted-Cross-Domain-Policies";

        /// <summary>
        /// The X-XSS-Protection header.
        /// </summary>
        public const string XXssProtection = "X-XSS-Protection";
    }
}
