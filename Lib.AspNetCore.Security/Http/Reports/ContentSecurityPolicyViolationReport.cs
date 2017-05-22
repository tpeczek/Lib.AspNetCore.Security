namespace Lib.AspNetCore.Security.Http.Reports
{
    /// <summary>
    /// Content Security Policy dispositions.
    /// </summary>
    public enum ContentSecurityPolicyDisposition
    {
        /// <summary>
        /// The "enforce" disposition.
        /// </summary>
        Enforce,
        /// <summary>
        /// The "report" disposition.
        /// </summary>
        Report
    }

    /// <summary>
    /// Represents Content-Security-Policy and Content-Security-Policy-Report-Only violation report.
    /// </summary>
    public class ContentSecurityPolicyViolationReport
    {
        #region Properties
        /// <summary>
        /// Gets the violation’s URL.
        /// </summary>
        public string DocumentUri { get; internal set; }

        /// <summary>
        /// Gets the referrer of the resource whose policy was violated.
        /// </summary>
        public string Referrer { get; internal set; }

        /// <summary>
        /// Gets the resource which violated the policy.
        /// </summary>
        public string BlockedUri { get; internal set; }

        /// <summary>
        /// Gets the directive whose enforcement caused the violation.
        /// </summary>
        public string EffectiveDirective { get; internal set; }

        /// <summary>
        /// Gets the directive whose enforcement caused the violation.
        /// </summary>
        public string ViolatedDirective { get; internal set; }

        /// <summary>
        /// Gets the violated policy.
        /// </summary>
        public string Policy { get; internal set; }

        /// <summary>
        /// Gets the violated policy disposition.
        /// </summary>
        public ContentSecurityPolicyDisposition Disposition { get; internal set; }

        /// <summary>
        /// Gets the HTTP status code of the resource for which the global object was instantiated.
        /// </summary>
        public int StatusCode { get; internal set; }

        /// <summary>
        /// Gets the sample.
        /// </summary>
        public string Sample { get; internal set; }

        /// <summary>
        /// Gets the violation’s source file URL.
        /// </summary>
        public string SourceFile { get; internal set; }

        /// <summary>
        /// Gets the violation’s line number.
        /// </summary>
        public int? LineNumber { get; internal set; }

        /// <summary>
        /// Gets the violation’s column number.
        /// </summary>
        public int? ColumnNumber { get; internal set; }
        #endregion
    }
}
