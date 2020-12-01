using LetsEncrypt.Logic.Config;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Logic
{
    public interface IRenewalService
    {
        /// <summary>
        /// When called will generate ONE new certificate for the given set of hostnames.
        /// This includes the verification with LetsEncrypt and the Azure resource update if necessary.
        /// </summary>
        /// <param name="options"></param>
        /// <param name="certRenewalOpts"></param>
        /// <param name="cancellationToken"></param>
        Task<RenewalResult> RenewCertificateAsync(IAcmeOptions options, CertificateRenewalOptions certRenewalOpts, CancellationToken cancellationToken);
    }
}
