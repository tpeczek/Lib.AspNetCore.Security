using System;
using System.Linq;
using System.Collections.Generic;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Represents value of Feature-Policy header.
    /// </summary>
    [Obsolete("Feature Policy has been replaced with Permissions Policy.")]
    public class MultipleFeaturePolicyHeaderValue : FeaturePolicyHeaderValue
    {
        #region Fields
        private readonly List<FeaturePolicy> _policies = new List<FeaturePolicy>();
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the policies to selectively enable and disable use of various browser features and APIs.
        /// </summary>
        public IList<FeaturePolicy> Policies => _policies;
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="MultipleFeaturePolicyHeaderValue"/> with single default <see cref="FeaturePolicy"/>.
        /// </summary>
        public MultipleFeaturePolicyHeaderValue()
        {
            Policies.Add(new FeaturePolicy());
        }

        /// <summary>
        /// Instantiates a new <see cref="MultipleFeaturePolicyHeaderValue"/>.
        /// </summary>
        /// <param name="policies">The policies to selectively enable and disable use of various browser features and APIs.</param>
        public MultipleFeaturePolicyHeaderValue(params FeaturePolicy[] policies)
        {
            _policies.AddRange(policies);
        }
        #endregion

        #region Methods
        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <returns>The string representation of header value.</returns>
        public override string ToString()
        {
            return String.Join(",", _policies.Select(policy => policy.ToPolicyDirectiveJson(true)));
        }
        #endregion
    }
}
