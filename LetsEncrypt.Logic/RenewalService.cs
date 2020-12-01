using Certes.Acme;
using Certes.Acme.Resource;
using LetsEncrypt.Logic.Acme;
using LetsEncrypt.Logic.Authentication;
using LetsEncrypt.Logic.Config;
using LetsEncrypt.Logic.Extensions;
using LetsEncrypt.Logic.Providers.CertificateStores;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Logic
{
    public class RenewalService : IRenewalService
    {
        private readonly ILogger _logger;
        private readonly IAuthenticationService _authenticationService;
        private readonly IRenewalOptionParser _renewalOptionParser;
        private readonly ICertificateBuilder _certificateBuilder;

        public RenewalService(
            IAuthenticationService authenticationService,
            IRenewalOptionParser renewalOptionParser,
            ICertificateBuilder certificateBuilder,
            ILogger<RenewalService> logger)
        {
            _authenticationService = authenticationService ?? throw new ArgumentNullException(nameof(authenticationService));
            _renewalOptionParser = renewalOptionParser ?? throw new ArgumentNullException(nameof(renewalOptionParser));
            _certificateBuilder = certificateBuilder ?? throw new ArgumentNullException(nameof(certificateBuilder));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<RenewalResult> RenewCertificateAsync(
            IAcmeOptions options,
            CertificateRenewalOptions certRenewalOpts,
            CancellationToken cancellationToken)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            if (certRenewalOpts == null)
                throw new ArgumentNullException(nameof(certRenewalOpts));

            var hostNames = string.Join(";", certRenewalOpts.HostNames);
            _logger.LogInformation($"Working on certificate for: {hostNames}");

            // 1. check if valid cert exists
            var cert = await GetExistingCertificateAsync(options, certRenewalOpts, cancellationToken);

            bool updateResource = false;
            if (cert == null)
            {
                // 2. run Let's Encrypt challenge as cert either doesn't exist or is expired
                _logger.LogInformation($"Issuing a new certificate for {hostNames}");
                var order = await ValidateOrderAsync(options, certRenewalOpts, cancellationToken);

                // 3. save certificate
                cert = await GenerateAndStoreCertificateAsync(order, certRenewalOpts, cancellationToken);
                updateResource = true;
            }

            var resource = _renewalOptionParser.ParseTargetResource(certRenewalOpts);
            // if no update is required still check with target resource
            // and only skip if latest cert is already used
            // this helps if cert issuance worked but resource updated failed
            // suggestion from https://github.com/MarcStan/lets-encrypt-azure/issues/6
            if (!updateResource &&
                (!resource.SupportsCertificateCheck ||
                await resource.IsUsingCertificateAsync(cert, cancellationToken)))
            {
                _logger.LogWarning(resource.SupportsCertificateCheck ?
                    $"Resource {resource.Name} ({resource.Type}) is already using latest certificate. Skipping resource update!" :
                    $"Cannot check resource {resource.Name} ({resource.Type}). Assuming it is already using latest certificate. Skipping resource update!");

                return RenewalResult.NoChange;
            }
            // 5. update Azure resource
            _logger.LogInformation($"Updating {resource.Name} ({resource.Type}) with certificates for {hostNames}");
            await resource.UpdateAsync(cert, cancellationToken);

            return RenewalResult.Success;
        }

        /// <summary>
        /// Checks if we have to renew the specific certificate just yet.
        /// </summary>
        /// <param name="options"></param>
        /// <param name="cfg"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>The cert if it is still valid according to rules in config. False otherwise.</returns>
        private async Task<ICertificate> GetExistingCertificateAsync(
            IAcmeOptions options,
            CertificateRenewalOptions cfg,
            CancellationToken cancellationToken)
        {
            if (cfg.Overrides.NewCertificate)
            {
                // ignore existing certificate
                _logger.LogWarning($"Override '{nameof(cfg.Overrides.NewCertificate)}' is enabled, forcing certificate renewal.");
                return null;
            }
            
            var certStore = _renewalOptionParser.ParseCertificateStore(cfg);

            // determine if renewal is needed based on existing cert
            var existingCert = await certStore.GetCertificateAsync(cancellationToken);

            // check if cert exists and that it is valid right now
            if (existingCert != null)
            {
                // handle cases of manually uploaded certificates
                if (!existingCert.Expires.HasValue)
                    throw new NotSupportedException($"Missing expiration value on certificate {existingCert.Name} (provider: {certStore.Type}). " +
                        "Must be set to expiration date of the certificate.");

                var now = DateTime.UtcNow;
                // must be valid now and some day in the future based on config expiration rule
                var isValidAlready = !existingCert.NotBefore.HasValue || existingCert.NotBefore.Value < now;
                var isStillValid = existingCert.Expires.Value.Date.AddDays(-options.RenewXDaysBeforeExpiry) >= now;
                if (isValidAlready && isStillValid)
                {
                    _logger.LogInformation($"Certificate {existingCert.Name} (from source: {certStore.Name}) is still valid until {existingCert.Expires.Value}. " +
                        $"Will be renewed in {(int)(existingCert.Expires.Value - now).TotalDays - options.RenewXDaysBeforeExpiry} days. Skipping renewal.");
                    return existingCert;
                }
                var reason = !isValidAlready ?
                    $"certificate won't be valid until {existingCert.NotBefore}" :
                    $"renewal is demanded {options.RenewXDaysBeforeExpiry} days before expiry and it is currently {(int)(existingCert.Expires.Value - now).TotalDays} days before expiry";

                _logger.LogInformation($"Certificate {existingCert.Name} (from source: {certStore.Name}) is no longer up to date ({reason}).");
            }
            // either no cert or expired
            return null;
        }

        /// <summary>
        /// Runs the LetsEncrypt challenge and verifies that it was completed successfully.
        /// </summary>
        /// <param name="options"></param>
        /// <param name="cfg"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>Returns the context, ready to generate certificate from.</returns>
        private async Task<IOrderContext> ValidateOrderAsync(
            IAcmeOptions options,
            CertificateRenewalOptions cfg,
            CancellationToken cancellationToken)
        {
            var acmeAuthContext = await _authenticationService.AuthenticateAsync(options, cancellationToken);
            var order = await acmeAuthContext.AcmeContext.NewOrder(cfg.HostNames);

            var challenge = await _renewalOptionParser.ParseChallengeResponderAsync(cfg, cancellationToken);

            var challengeContexts = await challenge.InitiateChallengesAsync(order, cancellationToken);

            if (challengeContexts.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(challengeContexts));

            try
            {
                // validate domain ownership
                await ValidateDomainOwnershipAsync(challengeContexts, cancellationToken);
            }
            finally
            {
                await challenge.CleanupAsync(challengeContexts, cancellationToken);
            }
            return order;
        }

        private async Task ValidateDomainOwnershipAsync(IChallengeContext[] challengeContexts, CancellationToken cancellationToken)
        {
            // let Let's Encrypt know that they can verify the challenge
            await Task.WhenAll(challengeContexts.Select(c => c.Validate()));

            // fetch response from Let's encrypt regarding challenge success/failure
            Challenge[] challengeResponses = null;
            do
            {
                if (challengeResponses != null)
                {
                    // wait before querying again
                    await Task.Delay(500, cancellationToken);
                }
                challengeResponses = await Task.WhenAll(challengeContexts.Select(c => c.Resource()));
            }
            while (challengeResponses.Any(c =>
                c.Status == ChallengeStatus.Pending ||
                c.Status == ChallengeStatus.Processing));

            ThrowIfNotInStatus(ChallengeStatus.Valid, challengeResponses);
        }

        private void ThrowIfNotInStatus(ChallengeStatus expectedStatus, Challenge[] challenges)
        {
            if (challenges.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(challenges));

            var failures = challenges
                .Where(c => c.Status != expectedStatus)
                .Select(f => f.Error)
                .ToArray();
            if (failures.Any())
            {
                var errors = string.Join(Environment.NewLine, failures.Select(f => f.Detail));
                throw new RenewalException($"Expected all challenges to be in status {expectedStatus}, but {failures.Length} where not: {errors}", failures);
            }
        }

        /// <summary>
        /// Creates a valid certificate from the order and uploads it to the store.
        /// </summary>
        /// <param name="order"></param>
        /// <param name="cfg"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>Returns metadata about the certificate.</returns>
        private async Task<ICertificate> GenerateAndStoreCertificateAsync(
            IOrderContext order,
            CertificateRenewalOptions cfg,
            CancellationToken cancellationToken)
        {
            var store = _renewalOptionParser.ParseCertificateStore(cfg);
            _logger.LogInformation($"Storing certificate in {store.Type} {store.Name}");

            // request certificate
            (byte[] pfxBytes, string password) = await _certificateBuilder.BuildCertificateAsync(order, cfg, cancellationToken);

            return await store.UploadAsync(pfxBytes, password, cfg.HostNames, cancellationToken);
        }
    }
}
