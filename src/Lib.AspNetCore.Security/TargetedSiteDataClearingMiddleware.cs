using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Lib.AspNetCore.Security.Http.Extensions;

namespace Lib.AspNetCore.Security
{
    /// <summary>
    /// Middleware which provides support for targeted site data clearing.
    /// </summary>
    public class TargetedSiteDataClearingMiddleware
    {
        #region Fields
        private readonly RequestDelegate _next;
        private readonly TargetedSiteDataClearingOptions _options;
        private IAntiforgery _antiforgery;
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="TargetedSiteDataClearingMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="options">An instance of the <see cref="TargetedSiteDataClearingOptions"/> to configure the middleware.</param>
        public TargetedSiteDataClearingMiddleware(RequestDelegate next, IOptions<TargetedSiteDataClearingOptions> options)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        }
        #endregion

        #region Methods
        /// <summary>
        /// Process an individual request.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public async Task Invoke(HttpContext context)
        {
            if (HttpMethods.IsPost(context.Request.Method))
            {
                if (_options.ValidateAntiforgery)
                {
                    EnsureAntiforgery(context);
                    await _antiforgery.ValidateRequestAsync(context);
                }

                context.Response.SetClearSiteData(_options.ClearSiteData);
            }

            await _next(context);
        }

        private void EnsureAntiforgery(HttpContext context)
        {
            if (_antiforgery == null)
            {
                _antiforgery = context.RequestServices.GetRequiredService<IAntiforgery>();
            }
        }
        #endregion
    }
}
