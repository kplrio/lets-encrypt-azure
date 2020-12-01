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
    /// Policy description details.
    /// </summary>
    [JsonTransformation]
    public partial class PolicyDescriptionContract : Resource
    {
        /// <summary>
        /// Initializes a new instance of the PolicyDescriptionContract class.
        /// </summary>
        public PolicyDescriptionContract()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the PolicyDescriptionContract class.
        /// </summary>
        /// <param name="id">Resource ID.</param>
        /// <param name="name">Resource name.</param>
        /// <param name="type">Resource type for API Management
        /// resource.</param>
        /// <param name="description">Policy description.</param>
        /// <param name="scope">Binary OR value of the Snippet scope.</param>
        public PolicyDescriptionContract(string id = default(string), string name = default(string), string type = default(string), string description = default(string), int? scope = default(int?))
            : base(id, name, type)
        {
            Description = description;
            Scope = scope;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets policy description.
        /// </summary>
        [JsonProperty(PropertyName = "properties.description")]
        public string Description { get; private set; }

        /// <summary>
        /// Gets binary OR value of the Snippet scope.
        /// </summary>
        [JsonProperty(PropertyName = "properties.scope")]
        public int? Scope { get; private set; }

    }
}