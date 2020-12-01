using LetsEncrypt.Logic.Providers.CertificateStores;
using LetsEncrypt.Logic.Providers.ChallengeResponders;
using LetsEncrypt.Logic.Providers.TargetResources;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Logic.Config
{
    public interface IRenewalOptionParser
    {
        /// <summary>
        /// Given a configuration object parses the challenge responder section based on its type and returns a statically typed version.
        /// </summary>
        /// <param name="cfg"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<IChallengeResponder> ParseChallengeResponderAsync(CertificateRenewalOptions cfg, CancellationToken cancellationToken);

        /// <summary>
        /// Given a configuration object parses the certificate storesection based on its type and returns a statically typed version.
        /// </summary>
        /// <param name="cfg"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        ICertificateStore ParseCertificateStore(CertificateRenewalOptions cfg);

        /// <summary>
        /// Given a configuration object parses the target resource section based on its type and returns a statically typed version.
        /// </summary>
        /// <param name="certRenewalOpts"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        ITargetResource ParseTargetResource(CertificateRenewalOptions certRenewalOpts);
    }
}
