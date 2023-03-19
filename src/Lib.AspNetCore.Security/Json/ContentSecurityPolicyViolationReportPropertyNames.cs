namespace Lib.AspNetCore.Security.Json
{
    internal static class ContentSecurityPolicyViolationReportPropertyNames
    {
        public const string CSP_REPORT = "csp-report";

        public const string DOCUMENT_URI = "document-uri";

        public const string REFERRER = "referrer";

        public const string BLOCKED_URI = "blocked-uri";

        public const string EFFECTIVE_DIRECTIVE = "effective-directive";

        public const string VIOLATED_DIRECTIVE = "violated-directive";

        public const string ORIGINAL_POLICY = "original-policy";

        public const string DISPOSITION = "disposition";

        public const string STATUS_CODE = "status-code";

        public const string SCRIPT_SAMPLE = "script-sample";

        public const string SOURCE_FILE = "source-file";

        public const string LINE_NUMBER = "line-number";

        public const string COLUMN_NUMBER = "column-number";
    }
}
