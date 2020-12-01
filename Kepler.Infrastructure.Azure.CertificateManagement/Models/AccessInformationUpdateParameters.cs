// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement.Models
{
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Tenant access information update parameters.
    /// </summary>
    [JsonTransformation]
    public partial class AccessInformationUpdateParameters
    {
        /// <summary>
        /// Initializes a new instance of the AccessInformationUpdateParameters
        /// class.
        /// </summary>
        public AccessInformationUpdateParameters()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the AccessInformationUpdateParameters
        /// class.
        /// </summary>
        /// <param name="enabled">Determines whether direct access is
        /// enabled.</param>
        public AccessInformationUpdateParameters(bool? enabled = default(bool?))
        {
            Enabled = enabled;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets determines whether direct access is enabled.
        /// </summary>
        [JsonProperty(PropertyName = "properties.enabled")]
        public bool? Enabled { get; set; }

    }
}
