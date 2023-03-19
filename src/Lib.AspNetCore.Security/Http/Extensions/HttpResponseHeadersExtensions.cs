using System;
using Microsoft.AspNetCore.Http;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security.Http.Extensions
{
    /// <summary>
    /// Extensions for setting response headers.
    /// </summary>
    public static class HttpResponseHeadersExtensions
    {
        #region Fields
        private const string _xContentTypeOptionsNoSniffDirective = "nosniff";
        private const string _xXDownloadOptionsNoOpenDirective = "noopen";
        #endregion

        #region Methods
        /// <summary>
        /// Sets the Clear-Site-Data header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="clearSiteData">The Clear-Site-Data header value.</param>
        public static void SetClearSiteData(this HttpResponse response, ClearSiteDataHeaderValue clearSiteData)
        {
            response.SetResponseHeader(HeaderNames.ClearSiteData, clearSiteData?.ToString());
        }

        /// <summary>
        /// Sets the Clear-Site-Data header value with wildcard pseudotype which indicates that all data types supported by header should be cleared (this is forward-compatible).
        /// </summary>
        /// <param name="response">The response.</param>
        public static void SetWildcardClearSiteData(this HttpResponse response)
        {
            response.SetResponseHeader(HeaderNames.ClearSiteData, ClearSiteDataHeaderValue.WildcardPseudotype);
        }

        /// <summary>
        /// Sets the HTTP Strict Transport Security header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="hsts">The HTTP Strict Transport Security header value.</param>
        public static void SetStrictTransportSecurity(this HttpResponse response, StrictTransportSecurityHeaderValue hsts)
        {
            response.SetResponseHeader(HeaderNames.StrictTransportSecurity, hsts?.ToString());
        }

        /// <summary>
        /// Sets the Expect-CT header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="expectCt">The Expect-CT header value.</param>
        public static void SetExpectCt(this HttpResponse response, ExpectCtHeaderValue expectCt)
        {
            response.SetResponseHeader(HeaderNames.ExpectCt, expectCt?.ToString());
        }

        /// <summary>
        /// Sets the Feature-Policy header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="featurePolicy">The Feature-Policy header value.</param>
        [Obsolete("Feature Policy has been replaced with Permissions Policy.")]
        public static void SetFeaturePolicy(this HttpResponse response, FeaturePolicyHeaderValue featurePolicy)
        {
            response.SetResponseHeader(HeaderNames.FeaturePolicy, featurePolicy?.ToString());
        }

        /// <summary>
        /// Sets the Permissions-Policy header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="permissionsPolicy">The Permissions-Policy header value.</param>
        public static void SetPermissionsPolicy(this HttpResponse response, PermissionsPolicyHeaderValue permissionsPolicy)
        {
            response.SetResponseHeader(HeaderNames.PermissionsPolicy, permissionsPolicy?.ToString());
        }

        /// <summary>
        /// Sets the Referrer-Policy header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="directive">The directive.</param>
        public static void SetReferrerPolicy(this HttpResponse response, ReferrerPolicyDirectives directive)
        {
            response.SetReferrerPolicy(new ReferrerPolicyHeaderValue(directive));
        }

        /// <summary>
        /// Sets the Referrer-Policy header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="referrerPolicy">The Referrer-Policy header value.</param>
        public static void SetReferrerPolicy(this HttpResponse response, ReferrerPolicyHeaderValue referrerPolicy)
        {
            response.SetResponseHeader(HeaderNames.ReferrerPolicy, referrerPolicy?.ToString());
        }

        /// <summary>
        /// Sets the X-Content-Type-Options header.
        /// </summary>
        /// <param name="response">The response.</param>
        public static void SetXContentTypeOptions(this HttpResponse response)
        {
            response.SetResponseHeader(HeaderNames.XContentTypeOptions, _xContentTypeOptionsNoSniffDirective);
        }

        /// <summary>
        /// Sets the X-Download-Options header.
        /// </summary>
        /// <param name="response">The response.</param>
        public static void SetXDownloadOptions(this HttpResponse response)
        {
            response.SetResponseHeader(HeaderNames.XDownloadOptions, _xXDownloadOptionsNoOpenDirective);
        }

        /// <summary>
        /// Sets the X-Frame-Options header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="xFrameOptions">The X-Frame-Options header value.</param>
        public static void SetXFrameOptions(this HttpResponse response, XFrameOptionsHeaderValue xFrameOptions)
        {
            response.SetResponseHeader(HeaderNames.XFrameOptions, xFrameOptions?.ToString());
        }

        /// <summary>
        /// Sets the X-Permitted-Cross-Domain-Policies header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="directive">The directive.</param>
        public static void SetXPermittedCrossDomainPolicies(this HttpResponse response, XPermittedCrossDomainPoliciesDirectives directive)
        {
            response.SetXPermittedCrossDomainPolicies(new XPermittedCrossDomainPoliciesHeaderValue(directive));
        }

        /// <summary>
        /// Sets the X-Permitted-Cross-Domain-Policies header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="permittedCrossDomainPolicies">The X-Permitted-Cross-Domain-Policies header value.</param>
        public static void SetXPermittedCrossDomainPolicies(this HttpResponse response, XPermittedCrossDomainPoliciesHeaderValue permittedCrossDomainPolicies)
        {
            response.SetResponseHeader(HeaderNames.XPermittedCrossDomainPolicies, permittedCrossDomainPolicies?.ToString());
        }

        /// <summary>
        /// Sets the X-XSS-Protection header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="filteringMode">The filtering mode.</param>
        public static void SetXXssProtection(this HttpResponse response, XssFilteringModes filteringMode)
        {
            response.SetXXssProtection(new XXssProtectionHeaderValue(filteringMode));
        }

        /// <summary>
        /// Sets the X-XSS-Protection header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="xXssProtection">The X-XSS-Protection header value.</param>
        public static void SetXXssProtection(this HttpResponse response, XXssProtectionHeaderValue xXssProtection)
        {
            response.SetResponseHeader(HeaderNames.XXssProtection, xXssProtection?.ToString());
        }

        internal static void SetResponseHeader(this HttpResponse response, string headerName, string headerValue)
        {
            if (!String.IsNullOrWhiteSpace(headerValue))
            {
                if (response.Headers.ContainsKey(headerName))
                {
                    response.Headers[headerName] = headerValue;
                }
                else
                {
                    response.Headers.Append(headerName, headerValue);
                }
            }
        }
        #endregion
    }
}
