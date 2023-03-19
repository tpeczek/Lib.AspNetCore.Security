using System;
using System.Linq;
using System.Collections.Generic;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Represents value of Permissions-Policy header.
    /// </summary>
    public class PermissionsPolicyHeaderValue
    {
        #region Fields
        private readonly List<PolicyControlledFeature> _features = new List<PolicyControlledFeature>();
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the features controlled by Permissions Policy.
        /// </summary>
        public IList<PolicyControlledFeature> Features => _features;
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="PermissionsPolicyHeaderValue"/>.
        /// </summary>
        /// <param name="features">The features controlled by Permissions Policy.</param>
        public PermissionsPolicyHeaderValue(params PolicyControlledFeature[] features)
        {
            _features.AddRange(features);
        }
        #endregion

        #region Methods
        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <returns>The string representation of header value.</returns>
        public override string ToString()
        {
            return String.Join(",", _features.Select(feature => feature.ToString()));
        }
        #endregion
    }
}
