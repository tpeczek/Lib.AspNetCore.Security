using System;
using System.Text;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Represents value of Strict-Transport-Security header.
    /// </summary>
    public class StrictTransportSecurityHeaderValue
    {
        #region Fields
        /// <summary>
        /// The minimum value for <see cref="MaxAge"/> when <see cref="Preload"/> is set to true.
        /// </summary>
        public const uint MinimumPreloadMaxAge = 10886400;

        private const string _maxAgeDirectiveFormat = "max-age={0}";
        private const string _includeSubDomainsDirective = "; includeSubDomains";
        private const string _preloadDirective = "; preload";

        private uint _maxAge;
        private bool _includeSubDomains;
        private bool _preload;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the time (in seconds) that the browser should remember that this resource is only to be accessed using HTTPS.
        /// </summary>
        public uint MaxAge
        {
            get { return _maxAge; }

            set
            {
                _headerValue = null;
                _maxAge = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if this rule applies to all subdomains as well.
        /// </summary>
        public bool IncludeSubDomains
        {
            get { return _includeSubDomains; }

            set
            {
                _headerValue = null;
                _includeSubDomains = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if subscription to HSTS preload list (https://hstspreload.appspot.com/) should be confirmed.
        /// </summary>
        public bool Preload
        {
            get { return _preload; }

            set
            {
                _headerValue = null;
                _preload = value;
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="StrictTransportSecurityHeaderValue"/>.
        /// </summary>
        /// <param name="maxAge">The time (in seconds) that the browser should remember that this resource is only to be accessed using HTTPS.</param>
        public StrictTransportSecurityHeaderValue(uint maxAge)
        {
            _maxAge = maxAge;
            _includeSubDomains = false;
            _preload = false;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <returns>The string representation of header value.</returns>
        public override string ToString()
        {
            if (_headerValue == null)
            {
                if (_preload && (_maxAge < MinimumPreloadMaxAge))
                {
                    throw new InvalidOperationException("HSTS preload list subscription requires expiry to be at least eighteen weeks (10886400 seconds).");
                }

                if (_preload && !_includeSubDomains)
                {
                    throw new InvalidOperationException("HSTS preload list subscription requires subdomains to be included.");
                }

                StringBuilder headerValueBuilder = new StringBuilder();
                headerValueBuilder.AppendFormat(_maxAgeDirectiveFormat, _maxAge);

                if (_includeSubDomains)
                {
                    headerValueBuilder.Append(_includeSubDomainsDirective);
                }

                if (_preload)
                {
                    headerValueBuilder.Append(_preloadDirective);
                }

                _headerValue = headerValueBuilder.ToString();
            }

            return _headerValue;
        }
        #endregion
    }
}
