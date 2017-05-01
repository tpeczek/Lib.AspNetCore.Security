using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Middleware for handling security headers.
    /// </summary>
    public class SecurityHeadersMiddleware
    {
        #region Fields
        private readonly RequestDelegate _next;
        private readonly SecurityHeadersPolicy _policy;
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="SecurityHeadersMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="policy">An instance of the <see cref="SecurityHeadersPolicy"/> to be applied.</param>
        public SecurityHeadersMiddleware(RequestDelegate next, SecurityHeadersPolicy policy)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        }
        #endregion

        #region Methods
        /// <summary>
        /// Process an individual request.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public async Task Invoke(HttpContext context)
        {
            if (!HandleNonHstsRequest(context))
            {
                AppendResponseHeader(context, HeaderNames.StrictTransportSecurity, _policy.Hsts?.ToString());

                await _next(context);

                AppendResponseHeader(context, _policy.IsCspReportOnly ? HeaderNames.ContentSecurityPolicyReportOnly : HeaderNames.ContentSecurityPolicy, _policy.Csp?.ToString());
            }
        }

        private void AppendResponseHeader(HttpContext context, string headerName, string headerValue)
        {
            if (!String.IsNullOrWhiteSpace(headerValue))
            {
                context.Response.Headers.Append(headerName, headerValue);
            }
        }

        private bool HandleNonHstsRequest(HttpContext context)
        {
            bool handleNonHstsRequest = (_policy.Hsts != null) && !context.Request.IsHttps;

            if (handleNonHstsRequest)
            {
                if (!String.Equals(context.Request.Method, "GET", StringComparison.OrdinalIgnoreCase) && !String.Equals(context.Request.Method, "HEAD", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                }
                else
                {
                    HostString host = (_policy.SslPort.HasValue && (_policy.SslPort > 0)) ? new HostString(context.Request.Host.Host, _policy.SslPort.Value) : new HostString(context.Request.Host.Host);

                    string location = String.Concat("https://",
                        host.ToUriComponent(),
                        context.Request.PathBase.ToUriComponent(),
                        context.Request.Path.ToUriComponent(),
                        context.Request.QueryString.ToUriComponent());

                    context.Response.Redirect(location, true);
                }
            }

            return handleNonHstsRequest;
        }
        #endregion
    }
}
