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
    /// Defines headers for CreateOrUpdate operation.
    /// </summary>
    public partial class IdentityProviderCreateOrUpdateHeaders
    {
        /// <summary>
        /// Initializes a new instance of the
        /// IdentityProviderCreateOrUpdateHeaders class.
        /// </summary>
        public IdentityProviderCreateOrUpdateHeaders()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the
        /// IdentityProviderCreateOrUpdateHeaders class.
        /// </summary>
        /// <param name="eTag">Current entity state version. Should be treated
        /// as opaque and used to make conditional HTTP requests.</param>
        public IdentityProviderCreateOrUpdateHeaders(string eTag = default(string))
        {
            ETag = eTag;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets current entity state version. Should be treated as
        /// opaque and used to make conditional HTTP requests.
        /// </summary>
        [JsonProperty(PropertyName = "ETag")]
        public string ETag { get; set; }

    }
}
