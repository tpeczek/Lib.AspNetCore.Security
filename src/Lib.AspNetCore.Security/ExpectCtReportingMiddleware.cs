using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Lib.AspNetCore.Security.Json;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Middleware which provides support for Expect-CT violation reports.
    /// </summary>
    public class ExpectCtReportingMiddleware
    {
        #region Fields
        private const string _expectCtReportContentType = "application/expect-ct-report";

        private readonly RequestDelegate _next;
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="ExpectCtReportingMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        public ExpectCtReportingMiddleware(RequestDelegate next)
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
            if (IsExpectCtReportRequest(context.Request))
            {
                ExpectCtViolationReport report = await ExpectCtViolationReportJsonDeserializer.DeserializeAsync(context.Request.Body);

                if (report != null)
                {
                    ISecurityHeadersReportingService securityHeadersReportingService = context.RequestServices.GetRequiredService<ISecurityHeadersReportingService>();

                    await securityHeadersReportingService.OnExpectCtViolationAsync(report);
                }

                context.Response.StatusCode = StatusCodes.Status204NoContent;
            }
            else
            {
                await _next(context);
            }
        }

        private bool IsExpectCtReportRequest(HttpRequest request)
        {
            return HttpMethods.IsPost(request.Method) && (request.ContentType == _expectCtReportContentType);
        }
        #endregion
    }
}
