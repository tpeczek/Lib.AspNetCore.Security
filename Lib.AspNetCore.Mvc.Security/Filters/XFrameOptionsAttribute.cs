using System;
using Microsoft.AspNetCore.Mvc.Filters;
using Lib.AspNetCore.Security.Http.Headers;
using Lib.AspNetCore.Security.Http.Extensions;

namespace Lib.AspNetCore.Mvc.Security.Filters
{
    /// <summary>
    /// Action filter for setting X-Frame-Options header value.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class XFrameOptionsAttribute : ActionFilterAttribute
    {
        #region Fields
        private readonly XFrameOptionsDirectives _directive;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the serialized origin for <see cref="XFrameOptionsDirectives.AllowFrom"/> directive.
        /// </summary>
        public string Origin { get; set; }
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="XFrameOptionsAttribute"/>.
        /// </summary>
        /// <param name="directive">The directive.</param>
        public XFrameOptionsAttribute(XFrameOptionsDirectives directive)
        {
            _directive = directive;
        }

        /// <summary>
        /// Instantiates a new <see cref="XFrameOptionsAttribute"/> with <see cref="XFrameOptionsDirectives.AllowFrom"/> directive.
        /// </summary>
        /// <param name="origin">The serialized origin.</param>
        public XFrameOptionsAttribute(string origin)
        {
            _directive = XFrameOptionsDirectives.AllowFrom;
            Origin = origin;
        }
        #endregion

        #region IActionFilter Members
        /// <summary>
        /// Called after the action method executes.
        /// </summary>
        /// <param name="context">The context.</param>
        public override void OnActionExecuted(ActionExecutedContext context)
        {
            context.HttpContext.Response.SetXFrameOptions(new XFrameOptionsHeaderValue(_directive) { Origin = Origin });
        }
        #endregion
    }
}
