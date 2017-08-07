using System;
using System.Text;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Represents value of Expect-CT header.
    /// </summary>
    public class ExpectCtHeaderValue
    {
        #region Fields
        /// <summary>
        /// The default value for <see cref="MaxAge"/> (30 days).
        /// </summary>
        public const uint DefauMaxAge = 2592000;

        /// <summary>
        /// The value for <see cref="MaxAge"/> in report-only mode.
        /// </summary>
        public const uint ReportOnlyMaxAge = 0;

        private const string _maxAgeDirectiveFormat = "max-age={0}";
        private const string _enforceDirective = "; enforce";
        private const string _reportUriDirectiveFormat = "; report-uri=\"{0}\"";

        private uint _maxAge;
        private bool _enforce;
        private string _reportUri;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the number of seconds after the reception of the Expect-CT header field during which the client should regard the host from whom the message was received as a Known Expect-CT Host.
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
        /// Gets or sets the value indicating if compliance to the CT Policy should be enforced.
        /// </summary>
        public bool Enforce
        {
            get { return _enforce; }

            set
            {
                _headerValue = null;
                _enforce = value;
            }
        }

        /// <summary>
        /// Gets or sets the absolute URI to which the client should report Expect-CT failures.
        /// </summary>
        public string ReportUri
        {
            get { return _reportUri; }

            set
            {
                _headerValue = null;
                _reportUri = value;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="ExpectCtHeaderValue"/> with default <see cref="MaxAge"/>.
        /// </summary>
        public ExpectCtHeaderValue()
            : this(DefauMaxAge)
        { }

        /// <summary>
        /// Instantiates a new <see cref="ExpectCtHeaderValue"/>.
        /// </summary>
        /// <param name="maxAge">The number of seconds after the reception of the Expect-CT header field during which the client should regard the host from whom the message was received as a Known Expect-CT Host.</param>
        public ExpectCtHeaderValue(uint maxAge)
        {
            _maxAge = maxAge;
            _enforce = false;
            _reportUri = null;
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
                StringBuilder headerValueBuilder = new StringBuilder();
                headerValueBuilder.AppendFormat(_maxAgeDirectiveFormat, _maxAge);

                if (_enforce)
                {
                    headerValueBuilder.Append(_enforceDirective);
                }

                if (!String.IsNullOrWhiteSpace(_reportUri))
                {
                    headerValueBuilder.AppendFormat(_reportUriDirectiveFormat, _reportUri);
                }

                _headerValue = headerValueBuilder.ToString();
            }

            return _headerValue;
        }
        #endregion
    }
}
