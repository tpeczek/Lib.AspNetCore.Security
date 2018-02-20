using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Lib.AspNetCore.Security.Http.Headers;
using Lib.AspNetCore.Security.Http.Extensions;

namespace Lib.AspNetCore.Security.Authentication
{
    internal class ClearSiteDataAuthenticationService : IAuthenticationService
    {
        #region Fields
        private readonly IAuthenticationService _authenticationService;
        private readonly ClearSiteDataHeaderValue _clearSiteDataHeaderValue;
        #endregion

        #region Constructor
        public ClearSiteDataAuthenticationService(IAuthenticationService authenticationService, ClearSiteDataHeaderValue clearSiteDataHeaderValue)
        {
            _authenticationService = authenticationService ?? throw new ArgumentNullException(nameof(authenticationService));
            _clearSiteDataHeaderValue = clearSiteDataHeaderValue ?? throw new ArgumentNullException(nameof(clearSiteDataHeaderValue));
        }
        #endregion

        #region Methods
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme)
        {
            return _authenticationService.AuthenticateAsync(context, scheme);
        }

        public Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            return _authenticationService.ChallengeAsync(context, scheme, properties);
        }

        public Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            return _authenticationService.ForbidAsync(context, scheme, properties);
        }

        public Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            return _authenticationService.SignInAsync(context, scheme, principal, properties);
        }

        public async Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            await _authenticationService.SignOutAsync(context, scheme, properties);

            if (context.User?.Identity?.IsAuthenticated ?? false)
            {
                context.Response.SetClearSiteData(_clearSiteDataHeaderValue);
            }
        }
        #endregion
    }
}
