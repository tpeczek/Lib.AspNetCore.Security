using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Exposes methods to build a <see cref="SecurityHeadersPolicy"/>.
    /// </summary>
    public class SecurityHeadersPolicyBuilder
    {
        #region Fields
        private readonly SecurityHeadersPolicy _policy = new SecurityHeadersPolicy();
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="SecurityHeadersPolicyBuilder"/>.
        /// </summary>
        public SecurityHeadersPolicyBuilder()
        { }
        #endregion

        #region Methods
        /// <summary>
        /// Adds the HTTP Strict Transport Security to the policy.
        /// </summary>
        /// <param name="maxAge">The time (in seconds) that the browser should remember that this resource is only to be accessed using HTTPS.</param>
        /// <param name="includeSubDomains">Tthe value indicating if this rule applies to all subdomains as well.</param>
        /// <param name="preload">The value indicating if subscription to HSTS preload list should be confirmed.</param>
        /// <param name="sslPort">The SSL port used by application.</param>
        /// <returns>The current policy builder.</returns>
        public SecurityHeadersPolicyBuilder WithHsts(uint maxAge, bool includeSubDomains = false, bool preload = false, int? sslPort = null)
        {
            _policy.Hsts = new StrictTransportSecurityHeaderValue(maxAge)
            {
                IncludeSubDomains = includeSubDomains,
                Preload = preload
            };
            _policy.SslPort = sslPort;

            return this;
        }

        /// <summary>
        /// Builds a new <see cref="SecurityHeadersPolicy"/> using the settings added.
        /// </summary>
        /// <returns>The constructed <see cref="SecurityHeadersPolicy"/>.</returns>
        public SecurityHeadersPolicy Build()
        {
            return _policy;
        }
        #endregion
    }
}
