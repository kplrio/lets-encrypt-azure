using LetsEncrypt.Logic.Azure;
using LetsEncrypt.Logic.Config.Properties;
using LetsEncrypt.Logic.Extensions;
using LetsEncrypt.Logic.Providers.CertificateStores;
using LetsEncrypt.Logic.Providers.ChallengeResponders;
using LetsEncrypt.Logic.Providers.TargetResources;
using LetsEncrypt.Logic.Storage;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Storage;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Logic.Config
{
    public class RenewalOptionParser : IRenewalOptionParser
    {
        public const string FileNameForPermissionCheck = "permission-check.blob";

        private readonly IAzureHelper _azureHelper;
        private readonly IKeyVaultClient _keyVaultClient;
        private readonly ILogger _logger;
        private readonly IStorageFactory _storageFactory;
        private readonly IAzureAppServiceClient _azureAppServiceClient;
        private readonly IAzureCdnClient _azureCdnClient;
        private readonly ILoggerFactory _loggerFactory;

        public RenewalOptionParser(
            IAzureHelper azureHelper,
            IKeyVaultClient keyVaultClient,
            IStorageFactory storageFactory,
            IAzureAppServiceClient azureAppServiceClient,
            IAzureCdnClient azureCdnClient,
            ILoggerFactory loggerFactory)
        {
            _azureHelper = azureHelper ?? throw new ArgumentNullException(nameof(azureHelper));
            _keyVaultClient = keyVaultClient ?? throw new ArgumentNullException(nameof(keyVaultClient));
            _storageFactory = storageFactory ?? throw new ArgumentNullException(nameof(storageFactory));
            _azureAppServiceClient = azureAppServiceClient;
            _azureCdnClient = azureCdnClient;
            _loggerFactory = loggerFactory;
            _logger = loggerFactory.CreateLogger<RenewalOptionParser>();
        }

        public async Task<IChallengeResponder> ParseChallengeResponderAsync(CertificateRenewalOptions cfg, CancellationToken cancellationToken)
        {
            var certStore = ParseCertificateStore(cfg);
            var target = ParseTargetResource(cfg);
            var cr = cfg.ChallengeResponder ?? new GenericEntry
            {
                Type = "storageAccount",
                Properties = JObject.FromObject(new StorageProperties
                {
                    AccountName = ConvertToValidStorageAccountName(target.Name),
                    KeyVaultName = certStore.Name
                })
            };
            switch (cr.Type.ToLowerInvariant())
            {
                case "storageaccount":
                    var props = cr.Properties?.ToObject<StorageProperties>() ?? new StorageProperties
                    {
                        KeyVaultName = cr.Name,
                        AccountName = ConvertToValidStorageAccountName(cr.Name)
                    };

                    // try MSI first, must do check if we can read to know if we have access
                    var accountName = props.AccountName;
                    if (string.IsNullOrEmpty(accountName))
                        accountName = ConvertToValidStorageAccountName(target.Name);

                    var storage = await _storageFactory.FromMsiAsync(accountName, props.ContainerName, cancellationToken);
                    // verify that MSI access works, fallback otherwise
                    // not ideal since it's a readonly check
                    // -> we need Blob Contributor for challenge persist but user could set Blob Reader and this check would pass
                    // alternative: write + delete a file from container as a check
                    try
                    {
                        await storage.ExistsAsync(FileNameForPermissionCheck, cancellationToken);
                    }
                    catch (StorageException e) when (e.RequestInformation.HttpStatusCode == (int)HttpStatusCode.Forbidden)
                    {
                        _logger.LogWarning($"MSI access to storage {accountName} failed. Attempting fallbacks via connection string. (You can ignore this warning if you don't use MSI authentication).");
                        var connectionString = props.ConnectionString;
                        if (string.IsNullOrEmpty(connectionString))
                        {
                            // falback to secret in keyvault
                            var keyVaultName = props.KeyVaultName;
                            if (string.IsNullOrEmpty(keyVaultName))
                                keyVaultName = certStore.Name;

                            _logger.LogInformation($"No connection string in config, checking keyvault {keyVaultName} secret {props.SecretName}");
                            connectionString = await GetSecretAsync(keyVaultName, props.SecretName, cancellationToken);
                        }
                        if (string.IsNullOrEmpty(connectionString))
                            throw new InvalidOperationException($"MSI access failed for {accountName} and could not find fallback connection string for storage access. Unable to proceed with Let's encrypt challenge");

                        storage = _storageFactory.FromConnectionString(connectionString, props.ContainerName);
                    }
                    return new AzureStorageHttpChallengeResponder(storage, props.Path);
                default:
                    throw new NotImplementedException(cr.Type);
            }
        }

        public ICertificateStore ParseCertificateStore(CertificateRenewalOptions cfg)
        {
            var target = ParseTargetResource(cfg);
            var store = cfg.CertificateStore ?? new GenericEntry
            {
                Type = "keyVault",
                Name = target.Name
            };

            switch (store.Type.ToLowerInvariant())
            {
                case "keyvault":
                    // all optional
                    var props = store.Properties?.ToObject<KeyVaultProperties>() ?? new KeyVaultProperties
                    {
                        Name = store.Name
                    };
                    var certificateName = props.CertificateName;
                    if (string.IsNullOrEmpty(certificateName))
                        certificateName = cfg.HostNames.First().Replace(".", "-");

                    var keyVaultName = props.Name;
                    if (string.IsNullOrEmpty(keyVaultName))
                        keyVaultName = target.Name;

                    var resourceGroupName = props.ResourceGroupName;
                    if (string.IsNullOrEmpty(resourceGroupName))
                        resourceGroupName = keyVaultName;

                    return new KeyVaultCertificateStore(_azureHelper, _keyVaultClient, keyVaultName, resourceGroupName, certificateName);
                default:
                    throw new NotImplementedException(store.Type);
            }
        }

        public ITargetResource ParseTargetResource(CertificateRenewalOptions certRenewalOpts)
        {
            switch (certRenewalOpts.TargetResource.Type.ToLowerInvariant())
            {
                case "cdn":
                    {
                        var cdnProps = certRenewalOpts.TargetResource.Properties == null
                            ? new CdnProperties
                            {
                                Endpoints = new[] { certRenewalOpts.TargetResource.Name },
                                Name = certRenewalOpts.TargetResource.Name,
                                ResourceGroupName = certRenewalOpts.TargetResource.Name
                            }
                            : certRenewalOpts.TargetResource.Properties.ToObject<CdnProperties>();

                        if (string.IsNullOrEmpty(cdnProps.Name))
                            throw new ArgumentException($"CDN section is missing required property {nameof(cdnProps.Name)}");

                        var propsResourceGroupName = cdnProps.ResourceGroupName;
                        if (string.IsNullOrEmpty(propsResourceGroupName))
                            throw new ArgumentNullException(nameof(certRenewalOpts.TargetResource));

                        if (cdnProps.Endpoints.IsNullOrEmpty())
                            cdnProps.Endpoints = new[] { cdnProps.Name };

                        return new CdnTargetResoure(_azureCdnClient, propsResourceGroupName, cdnProps.Name, cdnProps.Endpoints, _loggerFactory.CreateLogger<CdnTargetResoure>());
                    }
                case "appservice":
                    {
                        var props = certRenewalOpts.TargetResource.Properties == null
                            ? new AppServiceProperties
                            {
                                Name = certRenewalOpts.TargetResource.Name,
                                ResourceGroupName = certRenewalOpts.TargetResource.Name
                            }
                            : certRenewalOpts.TargetResource.Properties.ToObject<AppServiceProperties>();

                        if (string.IsNullOrEmpty(props.Name))
                            throw new ArgumentException($"AppService section is missing required property {nameof(props.Name)}");

                        var rg = props.ResourceGroupName;
                        if (string.IsNullOrEmpty(rg))
                            rg = props.Name;

                        return new AppServiceTargetResoure(_azureAppServiceClient, rg, props.Name, _loggerFactory.CreateLogger<AppServiceTargetResoure>());
                    }
                case "apigateway":
                {
                    throw new NotImplementedException();
                        break;
                    }
                default:
                    throw new NotImplementedException(certRenewalOpts.TargetResource.Type);
            }
        }

        /// <summary>
        /// Given a valid azure resource name converts it to the equivalent storage name by removing all dashes
        /// as per the usual convention used everywhere.
        /// </summary>
        /// <param name="resourceName"></param>
        /// <returns></returns>
        private string ConvertToValidStorageAccountName(string resourceName)
            => resourceName?.Replace("-", "");

        private async Task<string> GetSecretAsync(string keyVaultName, string secretName, CancellationToken cancellationToken)
        {
            try
            {
                var secret = await _keyVaultClient.GetSecretAsync($"https://{keyVaultName}.vault.azure.net", secretName, cancellationToken);
                return secret.Value;
            }
            catch (KeyVaultErrorException ex)
            {
                if (ex.Response.StatusCode == HttpStatusCode.Forbidden)
                {
                    _logger.LogError(ex, $"Access forbidden. Unable to get secret from keyvault {keyVaultName}");
                    throw;
                }
                if (ex.Response.StatusCode == HttpStatusCode.NotFound ||
                    ex.Body.Error.Code == "SecretNotFound")
                    return null;

                throw;
            }
            catch (HttpRequestException e)
            {
                _logger.LogError(e, $"Unable to get secret from keyvault {keyVaultName}");
                throw;
            }
        }
    }
}
