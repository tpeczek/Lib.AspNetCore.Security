using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Lib.AspNetCore.Security.Authentication;
using Lib.AspNetCore.Security.Http.Headers;


namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods for setting up authentication service which supports Clear-Site-Data header.
    /// </summary>
    public static class ClearSiteDataAuthenticationServiceCollectionExtensions
    {
        /// <summary>
        /// Add authentication service which supports Clear-Site-Data header.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="clearSiteDataHeaderValue">The Clear-Site-Data header value.</param>
        /// <returns>The service collection.</returns>
        public static IServiceCollection AddClearSiteDataAuthentication(this IServiceCollection services, ClearSiteDataHeaderValue clearSiteDataHeaderValue)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            ServiceDescriptor authenticationServiceDescriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IAuthenticationService));
            if (authenticationServiceDescriptor != null)
            {
                Type authenticationServiceImplementationType = authenticationServiceDescriptor.ImplementationType;
                ServiceLifetime authenticationServiceLifetime = authenticationServiceDescriptor.Lifetime;

                if (authenticationServiceImplementationType != null)
                {
                    services.Remove(authenticationServiceDescriptor);

                    services.Add(new ServiceDescriptor(authenticationServiceImplementationType, authenticationServiceImplementationType, authenticationServiceLifetime));

                    services.Add(new ServiceDescriptor(typeof(IAuthenticationService), (IServiceProvider serviceProvider) =>
                    {
                        IAuthenticationService authenticationService = (IAuthenticationService)serviceProvider.GetRequiredService(authenticationServiceImplementationType);

                        return new ClearSiteDataAuthenticationService(authenticationService, clearSiteDataHeaderValue);
                    }, authenticationServiceLifetime));
                }
            }

            return services;
        }
    }
}
