using System;
using System.Linq;
using System.Collections.ObjectModel;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Feature controlled by Permissions Policy.
    /// </summary>
    public class PolicyControlledFeature
    {
        #region Fields
        private string _permissionPolicyStructuredHeaderDictionaryValue = null;

        /// <summary>
        /// The allow list keyword to match current URL’s origin.
        /// </summary>
        public const string SelfOrigin = "self";
        #endregion

        #region Properties
        /// <summary>
        /// Gets the feature name.
        /// </summary>
        public string FeatureName { get; private set; }

        /// <summary>
        /// Indicates if the feature is allowed for all origins.
        /// </summary>
        public bool IsAllowedForAllOrigins { get; private set; } = false;

        /// <summary>
        /// Indicates if the feature should be disabled for all frames.
        /// </summary>
        public bool IsDeniedForAllOrigins { get; private set; } = false;

        /// <summary>
        /// Gets the allowlist (the set of allowed origins) for the feature.
        /// </summary>
        public ReadOnlyCollection<string> AllowList { get; private set; }
        #endregion

        #region Constructor
        private PolicyControlledFeature(string featureName)
        {
            if (String.IsNullOrWhiteSpace(featureName))
            {
                throw new ArgumentNullException(nameof(featureName));
            }

            FeatureName = featureName;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Creates a feature which is allowed for all origins.
        /// </summary>
        /// <param name="featureName">The feature name.</param>
        /// <returns>The feature controlled by Permissions Policy.</returns>
        public static PolicyControlledFeature CreateAllowedForAllOrigins(string featureName)
        {
            return new PolicyControlledFeature(featureName) { IsAllowedForAllOrigins = true };
        }

        /// <summary>
        /// Creates a feature which should be disabled for all frames.
        /// </summary>
        /// <param name="featureName">The feature name.</param>
        /// <returns>The feature controlled by Permissions Policy.</returns>
        public static PolicyControlledFeature CreateDeniedForAllOrigins(string featureName)
        {
            return new PolicyControlledFeature(featureName) { IsDeniedForAllOrigins = true };
        }

        /// <summary>
        /// Creates a feature which is allowed for origins on the allow list.
        /// </summary>
        /// <param name="featureName">The feature name.</param>
        /// <param name="allowList">The allowlist (the set of allowed origins) for the feature.</param>
        /// <returns>The feature controlled by Permissions Policy.</returns>
        public static PolicyControlledFeature CreateAllowedForAllowList(string featureName, params string[] allowList)
        {
            if (allowList is null || allowList.Length == 0)
            {
                throw new ArgumentNullException(nameof(allowList));
            }

            return new PolicyControlledFeature(featureName) { AllowList = Array.AsReadOnly(allowList) };
        }

        /// <summary>
        /// Gets the string representation of the feature policy.
        /// </summary>
        /// <returns>The string representation of the feature policy.</returns>
        public override string ToString()
        {
            if (_permissionPolicyStructuredHeaderDictionaryValue is null)
            {
                if (IsAllowedForAllOrigins)
                {
                    _permissionPolicyStructuredHeaderDictionaryValue = $"{FeatureName}=*";
                }
                else if (IsDeniedForAllOrigins)
                {
                    _permissionPolicyStructuredHeaderDictionaryValue = $"{FeatureName}=()";
                }
                else
                {
                    _permissionPolicyStructuredHeaderDictionaryValue = $"{FeatureName}=({String.Join(" ", AllowList.Select(origin => (origin == SelfOrigin) ? origin : '"' + origin + '"'))})";
                }
            }

            return _permissionPolicyStructuredHeaderDictionaryValue;
        }
        #endregion
    }
}
