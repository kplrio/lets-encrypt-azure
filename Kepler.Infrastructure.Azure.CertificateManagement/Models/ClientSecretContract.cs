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
    /// Client or app secret used in IdentityProviders, Aad, OpenID or OAuth.
    /// </summary>
    public partial class ClientSecretContract
    {
        /// <summary>
        /// Initializes a new instance of the ClientSecretContract class.
        /// </summary>
        public ClientSecretContract()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the ClientSecretContract class.
        /// </summary>
        /// <param name="clientSecret">Client or app secret used in
        /// IdentityProviders, Aad, OpenID or OAuth.</param>
        public ClientSecretContract(string clientSecret = default(string))
        {
            ClientSecret = clientSecret;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets client or app secret used in IdentityProviders, Aad,
        /// OpenID or OAuth.
        /// </summary>
        [JsonProperty(PropertyName = "clientSecret")]
        public string ClientSecret { get; set; }

    }
}