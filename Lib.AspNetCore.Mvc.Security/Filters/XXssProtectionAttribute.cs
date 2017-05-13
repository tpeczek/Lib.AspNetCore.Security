using System;
using Microsoft.AspNetCore.Mvc.Filters;
using Lib.AspNetCore.Security.Http.Headers;
using Lib.AspNetCore.Security.Http.Extensions;

namespace Lib.AspNetCore.Mvc.Security.Filters
{
    /// <summary>
    /// Action filter for setting X-XSS-Protection header value.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class XXssProtectionAttribute : ActionFilterAttribute
    {
        #region Properties
        /// <summary>
        /// Gets the filtering mode.
        /// </summary>
        public XssFilteringModes FilteringMode { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="XXssProtectionAttribute"/> with <see cref="XssFilteringModes.Sanitize"/> filtering mode.
        /// </summary>
        public XXssProtectionAttribute()
        {
            FilteringMode = XssFilteringModes.Sanitize;
        }

        /// <summary>
        /// Instantiates a new <see cref="XXssProtectionAttribute"/>.
        /// </summary>
        /// <param name="filteringMode">The filtering mode.</param>
        public XXssProtectionAttribute(XssFilteringModes filteringMode)
        {
            FilteringMode = filteringMode;
        }
        #endregion

        #region IActionFilter Members
        /// <summary>
        /// Called after the action method executes.
        /// </summary>
        /// <param name="context">The context.</param>
        public override void OnActionExecuted(ActionExecutedContext context)
        {
            context.HttpContext.Response.SetXXssProtection(new XXssProtectionHeaderValue(FilteringMode));
        }
        #endregion
    }
}
