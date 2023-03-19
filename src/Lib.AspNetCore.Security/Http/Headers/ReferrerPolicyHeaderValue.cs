using System;
using System.Collections.Generic;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Possible Referrer-Policy header directives.
    /// </summary>
    public enum ReferrerPolicyDirectives
    {
        /// <summary>
        /// No referrer information is sent along with requests.
        /// </summary>
        NoReferrer,
        /// <summary>
        /// The origin is sent as referrer to a-priori as-much-secure destination (HTTPS->HTTPS), but isn't sent to a less secure destination (HTTPS->HTTP).
        /// </summary>
        NoReferrerWhenDowngrade,
        /// <summary>
        /// Only send the origin of the document as the referrer in all cases.
        /// </summary>
        Origin,
        /// <summary>
        /// Send a full URL when performing a same-origin request, but only send the origin of the document for other cases.
        /// </summary>
        OriginWhenCrossOrigin,
        /// <summary>
        /// A referrer will be sent for same-site origins, but cross-origin requests will contain no referrer information.
        /// </summary>
        SameOrigin,
        /// <summary>
        /// Only send the origin of the document as the referrer to a-priori as-much-secure destination (HTTPS->HTTPS), but don't send it to a less secure destination (HTTPS->HTTP).
        /// </summary>
        StrictOrigin,
        /// <summary>
        /// Send a full URL when performing a same-origin request, only send the origin of the document to a-priori as-much-secure destination (HTTPS->HTTPS), and send no header to a less secure destination (HTTPS->HTTP).
        /// </summary>
        StrictOriginWhenCrossOrigin,
        /// <summary>
        /// Send a full URL (stripped from parameters) when performing a a same-origin or cross-origin request.
        /// </summary>
        UnsafeUrl
    }

    /// <summary>
    /// Represents value of Referrer-Policy header.
    /// </summary>
    public class ReferrerPolicyHeaderValue
    {
        #region Fields
        private static readonly IDictionary<ReferrerPolicyDirectives, string> _directives = new Dictionary<ReferrerPolicyDirectives, string>
        {
            { ReferrerPolicyDirectives.NoReferrer, "no-referrer" },
            { ReferrerPolicyDirectives.NoReferrerWhenDowngrade, "no-referrer-when-downgrade" },
            { ReferrerPolicyDirectives.Origin, "origin" },
            { ReferrerPolicyDirectives.OriginWhenCrossOrigin, "origin-when-cross-origin" },
            { ReferrerPolicyDirectives.SameOrigin, "same-origin" },
            { ReferrerPolicyDirectives.StrictOrigin, "strict-origin" },
            { ReferrerPolicyDirectives.StrictOriginWhenCrossOrigin, "strict-origin-when-cross-origin" },
            { ReferrerPolicyDirectives.UnsafeUrl, "unsafe-url" },
        };

        private ReferrerPolicyDirectives _directive;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the directive.
        /// </summary>
        public ReferrerPolicyDirectives Directive
        {
            get { return _directive; }

            set
            {
                _headerValue = null;
                _directive = value;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="ReferrerPolicyHeaderValue"/>.
        /// </summary>
        /// <param name="directive">The directive.</param>
        public ReferrerPolicyHeaderValue(ReferrerPolicyDirectives directive)
        {
            _directive = directive;
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
                if (!_directives.ContainsKey(_directive))
                {
                    throw new NotSupportedException($"Not supported directive: {_directive}");
                }

                _headerValue = _directives[_directive];
            }

            return _headerValue;
        }
        #endregion
    }
}
