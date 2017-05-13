using System;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Possible XSS filtering modes for X-XSS-Protection header.
    /// </summary>
    public enum XssFilteringModes
    {
        /// <summary>
        /// No XSS filtering.
        /// </summary>
        None,
        /// <summary>
        /// If XSS attack is detected, the browser will sanitize the page.
        /// </summary>
        Sanitize,
        /// <summary>
        /// If XSS attack is detected, the browser will prevent rendering of the page.
        /// </summary>
        Block
    }

    /// <summary>
    /// Represents value of X-XSS-Protection header.
    /// </summary>
    public class XXssProtectionHeaderValue
    {
        #region Fields
        private const string _disableDirective = "0";
        private const string _enableDirective = "1";
        private const string _blockDirective = "1; mode=block";

        private XssFilteringModes _filteringMode;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the filtering mode.
        /// </summary>
        public XssFilteringModes FilteringMode
        {
            get { return _filteringMode; }

            set
            {
                _headerValue = null;
                _filteringMode = value;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="XXssProtectionHeaderValue"/> with <see cref="XssFilteringModes.Sanitize"/> filtering mode.
        /// </summary>
        public XXssProtectionHeaderValue()
        {
            _filteringMode = XssFilteringModes.Sanitize;
        }

        /// <summary>
        /// Instantiates a new <see cref="XXssProtectionHeaderValue"/>.
        /// </summary>
        /// <param name="filteringMode">The filtering mode.</param>
        public XXssProtectionHeaderValue(XssFilteringModes filteringMode)
        {
            _filteringMode = filteringMode;
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
                switch (_filteringMode)
                {
                    case XssFilteringModes.None:
                        _headerValue = _disableDirective;
                        break;
                    case XssFilteringModes.Sanitize:
                        _headerValue = _enableDirective;
                        break;
                    case XssFilteringModes.Block:
                        _headerValue = _blockDirective;
                        break;
                    default:
                        throw new NotSupportedException($"Not supported filtering mode: {_filteringMode}");
                }
            }

            return _headerValue;
        }
        #endregion
    }
}
