using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Lib.AspNetCore.Security.Json;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Middleware which provides support for Content-Security-Policy and Content-Security-Policy-Report-Only violation reports.
    /// </summary>
    public class ContentSecurityPolicyReportingMiddleware
    {
        #region Fields
        private const string _cspReportContentType = "application/csp-report";

        private readonly RequestDelegate _next;
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="ContentSecurityPolicyReportingMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        public ContentSecurityPolicyReportingMiddleware(RequestDelegate next)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
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
            if (IsCspReportRequest(context.Request))
            {
                ContentSecurityPolicyViolationReport report = await ContentSecurityPolicyViolationReportJsonDeserializer.DeserializeAsync(context.Request.Body);

                if (report != null)
                {
                    ISecurityHeadersReportingService securityHeadersReportingService = context.RequestServices.GetRequiredService<ISecurityHeadersReportingService>();

                    await securityHeadersReportingService.OnContentSecurityPolicyViolationAsync(report);
                }

                context.Response.StatusCode = StatusCodes.Status204NoContent;
            }
            else
            {
                await _next(context);
            }
        }

        private static bool IsCspReportRequest(HttpRequest request)
        {
            return HttpMethods.IsPost(request.Method) && (request.ContentType == _cspReportContentType);
        }
        #endregion
    }
}
