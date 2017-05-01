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
        /// Gets or sets the HTTP Strict Transport Security header value.
        /// </summary>
        public StrictTransportSecurityHeaderValue Hsts { get; set; }

        /// <summary>
        /// Gets or sets the SSL port used by application.
        /// </summary>
        public int? SslPort { get; set; }
        #endregion
    }
}
