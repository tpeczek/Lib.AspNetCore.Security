using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Defines the security headers policy.
    /// </summary>
    public class SecurityHeadersPolicy
    {
        #region Properties
        /// <summary>
        /// Gets or sets the Content-Security-Policy or Content-Security-Policy-Report-Only header value.
        /// </summary>
        public ContentSecurityPolicyHeaderValue Csp { get; set; }

        /// <summary>
        /// Gets or sets value indicating if the Csp property should be treated as Content-Security-Policy or Content-Security-Policy-Report-Only header value.
        /// </summary>
        public bool IsCspReportOnly { get; set; }

        /// <summary>
        /// Gets or sets the Expect-CT header value.
        /// </summary>
        public ExpectCtHeaderValue ExpectCt { get; set; }

        /// <summary>
        /// Gets or sets the Feature-Policy header value.
        /// </summary>
        public FeaturePolicyHeaderValue FeaturePolicy { get; set; }

        /// <summary>
        /// Gets or sets the HTTP Strict Transport Security header value.
        /// </summary>
        public StrictTransportSecurityHeaderValue Hsts { get; set; }

        /// <summary>
        /// Gets or sets the Referrer-Policy header value.
        /// </summary>
        public ReferrerPolicyHeaderValue ReferrerPolicy { get; set; }

        /// <summary>
        /// Gets or sets the SSL port used by application.
        /// </summary>
        public int? SslPort { get; set; }

        /// <summary>
        /// Gets or sets the value indicating if X-Content-Type-Options header should be set.
        /// </summary>
        public bool XContentTypeOptions { get; set; }

        /// <summary>
        /// Gets or sets the value indicating if X-Download-Options header should be set.
        /// </summary>
        public bool XDownloadOptions { get; set; }

        /// <summary>
        /// Gets or sets the X-Frame-Options header value.
        /// </summary>
        public XFrameOptionsHeaderValue XFrameOptions { get; set; }

        /// <summary>
        /// Gets or sets the X-Permitted-Cross-Domain-Policies header value.
        /// </summary>
        public XPermittedCrossDomainPoliciesHeaderValue XPermittedCrossDomainPolicies { get; set; }

        /// <summary>
        /// Gets or sets the X-XSS-Protection header value.
        /// </summary>
        public XXssProtectionHeaderValue XXssProtection { get; set; }
        #endregion
    }
}
