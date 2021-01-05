using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace DocFx.Net.Http.EncryptedContentEncoding
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        { }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDefaultFiles()
                .UseStaticFiles();
        }
    }
}
