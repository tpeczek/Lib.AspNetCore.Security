using System.Threading.Tasks;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Contract for service which provides support for security headers violations reporting.
    /// </summary>
    public interface ISecurityHeadersReportingService
    {
        /// <summary>
        /// This method will be called uppon receiving Content-Security-Policy and Content-Security-Policy-Report-Only violation report.
        /// </summary>
        /// <param name="report">The Content-Security-Policy or Content-Security-Policy-Report-Only violation report.</param>
        /// <returns>The task object representing the asynchronous operation</returns>
        Task OnContentSecurityPolicyViolationAsync(ContentSecurityPolicyViolationReport report);

        /// <summary>
        /// This method will be called uppon receiving Expect-CT violation report.
        /// </summary>
        /// <param name="report">The Expect-CT violation report.</param>
        /// <returns>The task object representing the asynchronous operation</returns>
        Task OnExpectCtViolationAsync(ExpectCtViolationReport report);
    }
}
