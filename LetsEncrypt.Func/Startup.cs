using LetsEncrypt.Func;
using LetsEncrypt.Logic;
using LetsEncrypt.Logic.Storage;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Net.Http;
using Apimanagement;
using Apimanagement.Models;
using LetsEncrypt.Func.Config;
using Microsoft.Extensions.Http;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;

[assembly: FunctionsStartup(typeof(Startup))]
namespace LetsEncrypt.Func
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            // internal storage (used for letsencrypt account metadata)
            builder.Services.AddSingleton<IStorageProvider>(new AzureBlobStorageProvider(Environment.GetEnvironmentVariable("AzureWebJobsStorage"), "letsencrypt"));

            var tokenProvider = new AzureServiceTokenProvider();
            var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
            builder.Services.AddSingleton<IKeyVaultClient>(keyVaultClient);

            builder.Services.Scan(scan =>
                scan.FromAssemblyOf<RenewalService>()
                    .AddClasses()
                    .AsMatchingInterface()
                    .WithTransientLifetime()
                    .FromAssemblyOf<Startup>()
                    .AddClasses()
                    .AsMatchingInterface()
                    .WithTransientLifetime());
        }
    }
}
