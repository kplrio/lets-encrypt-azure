// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Properties controlling TLS Certificate Validation.
    /// </summary>
    public partial class BackendTlsProperties
    {
        /// <summary>
        /// Initializes a new instance of the BackendTlsProperties class.
        /// </summary>
        public BackendTlsProperties()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the BackendTlsProperties class.
        /// </summary>
        /// <param name="validateCertificateChain">Flag indicating whether SSL
        /// certificate chain validation should be done when using self-signed
        /// certificates for this backend host.</param>
        /// <param name="validateCertificateName">Flag indicating whether SSL
        /// certificate name validation should be done when using self-signed
        /// certificates for this backend host.</param>
        public BackendTlsProperties(bool? validateCertificateChain = default(bool?), bool? validateCertificateName = default(bool?))
        {
            ValidateCertificateChain = validateCertificateChain;
            ValidateCertificateName = validateCertificateName;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets flag indicating whether SSL certificate chain
        /// validation should be done when using self-signed certificates for
        /// this backend host.
        /// </summary>
        [JsonProperty(PropertyName = "validateCertificateChain")]
        public bool? ValidateCertificateChain { get; set; }

        /// <summary>
        /// Gets or sets flag indicating whether SSL certificate name
        /// validation should be done when using self-signed certificates for
        /// this backend host.
        /// </summary>
        [JsonProperty(PropertyName = "validateCertificateName")]
        public bool? ValidateCertificateName { get; set; }

    }
}