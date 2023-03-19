using System;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Represents value of Feature-Policy header.
    /// </summary>
    [Obsolete("Feature Policy has been replaced with Permissions Policy.")]
    public class SingleFeaturePolicyHeaderValue : FeaturePolicyHeaderValue
    {
        #region Properties
        /// <summary>
        /// Gets or sets the policy to selectively enable and disable use of various browser features and APIs.
        /// </summary>
        public FeaturePolicy Policy { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="SingleFeaturePolicyHeaderValue"/> with default <see cref="Policy"/>.
        /// </summary>
        public SingleFeaturePolicyHeaderValue()
        {
            Policy = new FeaturePolicy();
        }

        /// <summary>
        /// Instantiates a new <see cref="SingleFeaturePolicyHeaderValue"/>.
        /// </summary>
        /// <param name="policy">The policy to selectively enable and disable use of various browser features and APIs.</param>
        public SingleFeaturePolicyHeaderValue(FeaturePolicy policy)
        {
            Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        }
        #endregion

        #region Methods
        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <returns>The string representation of header value.</returns>
        public override string ToString()
        {
            return Policy.ToPolicyDirectiveJson(true);
        }
        #endregion
    }
}
