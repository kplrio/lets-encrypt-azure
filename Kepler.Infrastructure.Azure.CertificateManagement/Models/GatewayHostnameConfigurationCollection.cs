// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement.Models
{
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Paged Gateway hostname configuration list representation.
    /// </summary>
    public partial class GatewayHostnameConfigurationCollection
    {
        /// <summary>
        /// Initializes a new instance of the
        /// GatewayHostnameConfigurationCollection class.
        /// </summary>
        public GatewayHostnameConfigurationCollection()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the
        /// GatewayHostnameConfigurationCollection class.
        /// </summary>
        /// <param name="value">Page values.</param>
        /// <param name="nextLink">Next page link if any.</param>
        public GatewayHostnameConfigurationCollection(IList<GatewayHostnameConfigurationContract> value = default(IList<GatewayHostnameConfigurationContract>), string nextLink = default(string))
        {
            Value = value;
            NextLink = nextLink;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets page values.
        /// </summary>
        [JsonProperty(PropertyName = "value")]
        public IList<GatewayHostnameConfigurationContract> Value { get; private set; }

        /// <summary>
        /// Gets next page link if any.
        /// </summary>
        [JsonProperty(PropertyName = "nextLink")]
        public string NextLink { get; private set; }

    }
}