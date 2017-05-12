using System;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Possible X-Frame-Options header directives.
    /// </summary>
    public enum XFrameOptionsDirectives
    {
        /// <summary>
        /// The page cannot be displayed in a frame, regardless of the site attempting to do so.
        /// </summary>
        Deny,
        /// <summary>
        /// The page can only be displayed in a frame on the same origin as the page itself.
        /// </summary>
        SameOrigin,
        /// <summary>
        /// The page can only be displayed in a frame on the specified origin.
        /// </summary>
        AllowFrom
    }

    /// <summary>
    /// Represents value of X-Frame-Options header.
    /// </summary>
    public class XFrameOptionsHeaderValue
    {
        #region Fields
        private const string _denyDirective = "DENY";
        private const string _sameOriginDirective = "SAMEORIGIN";
        private const string _allowFromDirectiveFormat = "ALLOW-FROM {0}";

        private XFrameOptionsDirectives _directive;
        private string _origin;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the directive.
        /// </summary>
        public XFrameOptionsDirectives Directive
        {
            get { return _directive; }

            set
            {
                _headerValue = null;
                _directive = value;
            }
        }

        /// <summary>
        /// Gets or sets the serialized origin for <see cref="XFrameOptionsDirectives.AllowFrom"/> directive.
        /// </summary>
        public string Origin
        {
            get { return _origin; }

            set
            {
                if (_directive == XFrameOptionsDirectives.AllowFrom)
                {
                    _headerValue = null;
                }

                _origin = value;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="XFrameOptionsHeaderValue"/>.
        /// </summary>
        /// <param name="directive">The directive.</param>
        public XFrameOptionsHeaderValue(XFrameOptionsDirectives directive)
        {
            _directive = directive;
        }

        /// <summary>
        /// Instantiates a new <see cref="XFrameOptionsHeaderValue"/> with <see cref="XFrameOptionsDirectives.AllowFrom"/> directive.
        /// </summary>
        /// <param name="origin">The serialized origin.</param>
        public XFrameOptionsHeaderValue(string origin)
        {
            _directive = XFrameOptionsDirectives.AllowFrom;
            _origin = origin;
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
                switch (_directive)
                {
                    case XFrameOptionsDirectives.Deny:
                        _headerValue = _denyDirective;
                        break;
                    case XFrameOptionsDirectives.SameOrigin:
                        _headerValue = _sameOriginDirective;
                        break;
                    case XFrameOptionsDirectives.AllowFrom:
                        if (String.IsNullOrWhiteSpace(_origin))
                        {
                            throw new InvalidOperationException($"The {nameof(XFrameOptionsDirectives.AllowFrom)} directive requires {nameof(Origin)} to have a value.");
                        }

                        _headerValue = String.Format(_allowFromDirectiveFormat, _origin);
                        break;
                    default:
                        throw new NotSupportedException($"Not support directive: {_directive}");
                }
            }

            return _headerValue;
        }
        #endregion
    }
}
