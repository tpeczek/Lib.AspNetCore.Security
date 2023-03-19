using System;
using System.Text;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Represents value of Clear-Site-Data header.
    /// </summary>
    public class ClearSiteDataHeaderValue
    {
        #region Fields
        internal const string WildcardPseudotype = "\"*\"";

        private const string _cacheType = "\"cache\",";
        private const string _cookiesType = "\"cookies\",";
        private const string _storageType = "\"storage\",";
        private const string _executionContextsType = "\"executionContexts\",";

        private bool _clearCache;
        private bool _clearCookies;
        private bool _clearStorage;
        private bool _clearExecutionContexts;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the value indicating if server wishes to remove locally cached data associated with the origin of a particular response’s url.
        /// </summary>
        public bool ClearCache
        {
            get { return _clearCache; }

            set
            {
                _headerValue = null;
                _clearCache = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if server wishes to remove cookies associated with the origin of a particular response’s url.
        /// </summary>
        public bool ClearCookies
        {
            get { return _clearCookies; }

            set
            {
                _headerValue = null;
                _clearCookies = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if server wishes to remove locally stored data associated with the origin of a particular response’s url.
        /// </summary>
        public bool ClearStorage
        {
            get { return _clearStorage; }

            set
            {
                _headerValue = null;
                _clearStorage = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if server wishes to neuter and reload execution contexts currently rendering the origin of a particular response’s url.
        /// </summary>
        public bool ClearExecutionContexts
        {
            get { return _clearExecutionContexts; }

            set
            {
                _headerValue = null;
                _clearExecutionContexts = value;
            }
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

                if (_clearCache)
                {
                    headerValueBuilder.Append(_cacheType);
                }

                if (_clearCookies)
                {
                    headerValueBuilder.Append(_cookiesType);
                }

                if (_clearStorage)
                {
                    headerValueBuilder.Append(_storageType);
                }

                if (_clearExecutionContexts)
                {
                    headerValueBuilder.Append(_executionContextsType);
                }

                if (headerValueBuilder.Length == 0)
                {
                    throw new InvalidOperationException("At least one data type must be selected.");
                }

                headerValueBuilder.Length -= 1;
                _headerValue = headerValueBuilder.ToString();
            }

            return _headerValue;
        }
        #endregion
    }
}
