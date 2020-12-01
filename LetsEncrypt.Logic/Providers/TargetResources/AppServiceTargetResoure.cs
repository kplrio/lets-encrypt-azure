using LetsEncrypt.Logic.Azure;
using LetsEncrypt.Logic.Extensions;
using LetsEncrypt.Logic.Providers.CertificateStores;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;


namespace LetsEncrypt.Logic.Providers.TargetResources
{
    public class APIGatewayTargetResource : ITargetResource
    {


        public string Name { get; set; }
        public string Type { get; set; }
        public bool SupportsCertificateCheck { get; set; }
        public async Task UpdateAsync(ICertificate cert, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public async Task<bool> IsUsingCertificateAsync(ICertificate cert, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
    public class AppServiceTargetResoure : ITargetResource
    {
        private readonly string _resourceGroupName;
        private readonly ILogger _logger;
        private readonly IAzureAppServiceClient _azureManagementClient;

        public AppServiceTargetResoure(
            IAzureAppServiceClient azureManagementClient,
            string resourceGroupName,
            string name,
            ILogger<AppServiceTargetResoure> logger)
        {
            _azureManagementClient = azureManagementClient ?? throw new ArgumentNullException(nameof(azureManagementClient));
            _resourceGroupName = resourceGroupName ?? throw new ArgumentNullException(nameof(resourceGroupName));
            Name = name ?? throw new ArgumentNullException(nameof(name));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }



        public string Name { get; }

        public string Type => "App Service";

        public bool SupportsCertificateCheck => true;

        public async Task<bool> IsUsingCertificateAsync(ICertificate cert, CancellationToken cancellationToken)
        {
            var response = await _azureManagementClient.GetAppServicePropertiesAsync(_resourceGroupName, Name, cancellationToken);
            // app service has one entry per domain, but we could have one cert that matched all
            var matched = response.CustomDomains
                .Where(x => cert.Thumbprint.Equals(x.Thumbprint, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            // verify that the cert covers all matching entries
            return
                matched.Length > 0 &&
                matched.All(x => cert.HostNames.Contains(x.HostName, StringComparison.OrdinalIgnoreCase));
        }

        public async Task UpdateAsync(ICertificate cert, CancellationToken cancellationToken)
        {
            if (cert.Store.Type != "keyVault")
                throw new NotSupportedException("App Service can only use certificates from store keyVault. Found: " + cert.Store.Type);

            // actually find the bindings which use the cert
            // e.g. cert input "www.example.com, example.com" will have two seperate bindings for the domains
            var response = await _azureManagementClient.GetAppServicePropertiesAsync(_resourceGroupName, Name, cancellationToken);

            // user may also provide X hostnames in cert, but then map them to Y different webapps
            // get hostnames from webapp and only return the matching set
            var hostnames = cert.HostNames
                .Where(h => response.CustomDomains.Any(x => x.HostName.Equals(h, StringComparison.OrdinalIgnoreCase)))
                .ToArray();

            if (!hostnames.Any())
                throw new InvalidOperationException($"Web app {Name} has no matching domain assigned to it from hostname set: {string.Join(", ", cert.HostNames)}");

            var formattedHostNames = string.Join(";", hostnames);
            // cert name should be unique in resourcegroup yet it must be possible to upload multiple certificates for the same domain to allow for cert rotation -> append thumbprint
            var hostName = hostnames.First();

            var certName = $"{hostName}-{cert.Thumbprint}";

            // documentation used to be adamant about keeping cert next to app service plan, but seems its now also possible to keep it next to web app itself (or any RG really)
            // (however cert can never be moved once it is bound) => keep next to app service plan for now
            var appServiceResourceGroupName = ParseResourceGroupFromResourceId(response.ServerFarmId);

            _logger.LogInformation($"Adding certificate {cert.Name} (thumprint: {cert.Thumbprint}, matchedHostNames: {formattedHostNames}) to resourcegroup {appServiceResourceGroupName} with name {certName}");

            var certificates = await _azureManagementClient.ListCertificatesAsync(appServiceResourceGroupName, cancellationToken);
            var alreadyUploaded = certificates.Any(c => c.Name == certName);
            if (!alreadyUploaded)
            {
                // only upload certificate into app service plan resource group
                // if not already found (allow for idempotence)
                await _azureManagementClient.UploadCertificateAsync(response, cert, certName, appServiceResourceGroupName, cancellationToken);
            }

            _logger.LogInformation($"Binding hostnames {formattedHostNames} on webapp {Name}");
            await _azureManagementClient.AssignDomainBindingsAsync(_resourceGroupName, Name, hostnames, cert, response.Location, cancellationToken);

            // remove all old certificates from resource groups they are no longer needed
            await CleanupOldCertificatesAsync(hostnames, cert, appServiceResourceGroupName, cancellationToken);
        }

        private async Task CleanupOldCertificatesAsync(string[] hostnames, ICertificate cert, string resourceGroupName, CancellationToken cancellationToken)
        {
            var certificates = await _azureManagementClient.ListCertificatesAsync(resourceGroupName, cancellationToken);

            var thumbprints = await cert.Store.GetCertificateThumbprintsAsync(cancellationToken);
            var oldThumbprints = thumbprints.Except(new[] { cert.Thumbprint }).ToArray();

            // only try delete certificates that were issued by this client
            // must match all hostnames and thumbprint to be considered for deletion
            var certificatesToDelete = certificates
                .Where(c => oldThumbprints.Contains(c.Thumbprint, StringComparison.OrdinalIgnoreCase) &&
                            c.HostNames.All(h => hostnames.Any(h2 => h.Equals(h2, StringComparison.OrdinalIgnoreCase))))
                .Select(c => c.Name)
                .ToList();

            _logger.LogInformation($"Removing old certificates ({string.Join(";", certificatesToDelete)}) as webapp {Name} no longer uses it.");
            foreach (var c in certificatesToDelete)
            {
                await _azureManagementClient.DeleteCertificateAsync(c, resourceGroupName, cancellationToken);
            }
        }

        private static string ParseResourceGroupFromResourceId(string serverFarmId)
        {
            var regex = new Regex(@"^\/subscriptions\/[\w-]+/resourceGroups\/([\w-]+)\/");

            var match = regex.Match(serverFarmId);
            if (!match.Success)
                throw new NotSupportedException($"Unable to parse resourcegroup from resourceId: {serverFarmId}");

            return match.Groups[1].Value;
        }
    }
}
