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
