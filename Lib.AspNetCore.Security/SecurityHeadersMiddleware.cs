using System;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Http;
using Lib.AspNetCore.Security.Http.Headers;
using Lib.AspNetCore.Security.Http.Features;
using Lib.AspNetCore.Security.Http.Extensions;


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
        private readonly ConcurrentDictionary<string, string> _hashesCache;

        private static Task _completedTask = Task.FromResult<object>(null);
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
            _hashesCache = new ConcurrentDictionary<string, string>();
        }
        #endregion

        #region Methods
        /// <summary>
        /// Process an individual request.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public Task Invoke(HttpContext context)
        {
            Task result = _completedTask;

            if (!HandleNonHstsRequest(context))
            {
                HandleCsp(context);

                HandleSingleDirectiveHeader(context.Response.SetXContentTypeOptions, _policy.XContentTypeOptions);
                HandleSingleDirectiveHeader(context.Response.SetXDownloadOptions, _policy.XDownloadOptions);

                context.Response.SetReferrerPolicy(_policy.ReferrerPolicy);
                context.Response.SetStrictTransportSecurity(_policy.Hsts);
                context.Response.SetXFrameOptions(_policy.XFrameOptions);
                context.Response.SetXPermittedCrossDomainPolicies(_policy.XPermittedCrossDomainPolicies);
                context.Response.SetXXssProtection(_policy.XXssProtection);

                if (context.Request.IsHttps)
                {
                    context.Response.SetExpectCt(_policy.ExpectCt);
                }

                result = _next(context);
            }

            return result;
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

        private void HandleCsp(HttpContext context)
        {
            if (_policy.Csp != null)
            {
                context.Features.Set<IContentSecurityPolicyInlineExecutionFeature>(new ContentSecurityPolicyInlineExecutionFeature(_policy.Csp, _hashesCache));

                context.Response.OnStarting(() => {
                    string headerName = _policy.IsCspReportOnly ? HeaderNames.ContentSecurityPolicyReportOnly : HeaderNames.ContentSecurityPolicy;

                    IContentSecurityPolicyInlineExecutionFeature cspFeature = context.Features.Get<IContentSecurityPolicyInlineExecutionFeature>();

                    context.Response.SetResponseHeader(headerName, _policy.Csp.ToString(cspFeature?.Nonce, cspFeature?.ScriptsHashes, cspFeature?.StylesHashes));

                    return _completedTask;
                });
            }
        }

        private static void HandleSingleDirectiveHeader(Action setHeaderAction, bool shouldSetHeader)
        {
            if (shouldSetHeader)
            {
                setHeaderAction();
            }
        }
        #endregion
    }
}
