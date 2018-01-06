using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;

namespace DocFx.Net.Http.EncryptedContentEncoding
{
    public class Program
    {
        public static void Main(string[] args) => WebHost.CreateDefaultBuilder(args).UseStartup<Startup>().Build().Run();
    }
}
