using System;
using System.Collections.Generic;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Possible X-Permitted-Cross-Domain-Policies header directives.
    /// </summary>
    public enum XPermittedCrossDomainPoliciesDirectives
    {
        /// <summary>
        /// No policy files are allowed anywhere on the target server, including master policy file.
        /// </summary>
        None,
        /// <summary>
        /// Only master policy file is allowed.
        /// </summary>
        MasterOnly,
        /// <summary>
        /// Only policy files served with Content-Type: text/x-cross-domain-policy are allowed.
        /// </summary>
        ByContentType,
        /// <summary>
        /// All policy files on this target domain are allowed.
        /// </summary>
        All
    }

    /// <summary>
    /// Represents value of X-Permitted-Cross-Domain-Policies header which is used for informing Adobe products (PDF, Flash) as to how to handle cross domain policies.
    /// </summary>
    public class XPermittedCrossDomainPoliciesHeaderValue
    {
        #region Fields
        private static readonly IDictionary<XPermittedCrossDomainPoliciesDirectives, string> _directives = new Dictionary<XPermittedCrossDomainPoliciesDirectives, string>
        {
            { XPermittedCrossDomainPoliciesDirectives.None, "none" },
            { XPermittedCrossDomainPoliciesDirectives.MasterOnly, "master-only" },
            { XPermittedCrossDomainPoliciesDirectives.ByContentType, "by-content-type" },
            { XPermittedCrossDomainPoliciesDirectives.All, "all" }
        };

        private XPermittedCrossDomainPoliciesDirectives _directive;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the directive.
        /// </summary>
        public XPermittedCrossDomainPoliciesDirectives Directive
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
        /// Instantiates a new <see cref="XPermittedCrossDomainPoliciesHeaderValue"/>.
        /// </summary>
        /// <param name="directive">The directive.</param>
        public XPermittedCrossDomainPoliciesHeaderValue(XPermittedCrossDomainPoliciesDirectives directive)
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
