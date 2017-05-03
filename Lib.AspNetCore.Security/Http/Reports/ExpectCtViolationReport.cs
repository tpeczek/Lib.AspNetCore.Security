using System;

namespace Lib.AspNetCore.Security.Http.Reports
{
    /// <summary>
    /// Represents Expect-CT violation report.
    /// </summary>
    public class ExpectCtViolationReport
    {
        #region Properties
        /// <summary>
        /// Gets the time the client observed the failure.
        /// </summary>
        public DateTime FailureDate { get; internal set; }

        /// <summary>
        /// Gets the hostname to which the client made the request.
        /// </summary>
        public string Hostname { get; internal set; }

        /// <summary>
        /// Gets the port to which the client made the original request.
        /// </summary>
        public int Port { get; internal set; }

        /// <summary>
        /// Gets the Effective Expiration Date for the Expect-CT Host.
        /// </summary>
        public DateTime EffectiveExpirationDate { get; internal set; }
        #endregion
    }
}
