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
        #region Methods
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
        /// Sets the X-Frame-Options header value.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="xFrameOptions">The X-Frame-Options header value.</param>
        public static void SetXFrameOptions(this HttpResponse response, XFrameOptionsHeaderValue xFrameOptions)
        {
            response.SetResponseHeader(HeaderNames.XFrameOptions, xFrameOptions?.ToString());
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
