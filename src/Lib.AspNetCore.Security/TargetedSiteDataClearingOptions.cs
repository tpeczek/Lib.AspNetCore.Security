using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Options for the <see cref="TargetedSiteDataClearingMiddleware"/> middleware.
    /// </summary>
    public class TargetedSiteDataClearingOptions
    {
        #region Properties
        internal ClearSiteDataHeaderValue ClearSiteData { get; } = new ClearSiteDataHeaderValue();

        /// <summary>
        /// Gets or sets the value indicating if server wishes to remove locally cached data associated with the origin of a particular response’s url.
        /// </summary>
        public bool ClearCache
        {
            get { return ClearSiteData.ClearCache; }

            set { ClearSiteData.ClearCache = value; }
        }

        /// <summary>
        /// Gets or sets the value indicating if server wishes to remove cookies associated with the origin of a particular response’s url.
        /// </summary>
        public bool ClearCookies
        {
            get { return ClearSiteData.ClearCookies; }

            set { ClearSiteData.ClearCookies = value; }
        }

        /// <summary>
        /// Gets or sets the value indicating if server wishes to remove locally stored data associated with the origin of a particular response’s url.
        /// </summary>
        public bool ClearStorage
        {
            get { return ClearSiteData.ClearStorage; }

            set { ClearSiteData.ClearStorage = value; }
        }

        /// <summary>
        /// Gets or sets the value indicating if server wishes to neuter and reload execution contexts currently rendering the origin of a particular response’s url.
        /// </summary>
        public bool ClearExecutionContexts
        {
            get { return ClearSiteData.ClearExecutionContexts; }

            set { ClearSiteData.ClearExecutionContexts = value; }
        }

        /// <summary>
        /// Gets or sets the value indicating if an antiforgery token that was supplied as part of the request should be validated.
        /// </summary>
        public bool ValidateAntiforgery { get; set; } = true;
        #endregion
    }
}
