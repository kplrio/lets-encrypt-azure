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
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Api Operation Update Contract details.
    /// </summary>
    [JsonTransformation]
    public partial class OperationUpdateContract
    {
        /// <summary>
        /// Initializes a new instance of the OperationUpdateContract class.
        /// </summary>
        public OperationUpdateContract()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the OperationUpdateContract class.
        /// </summary>
        /// <param name="templateParameters">Collection of URL template
        /// parameters.</param>
        /// <param name="description">Description of the operation. May include
        /// HTML formatting tags.</param>
        /// <param name="request">An entity containing request details.</param>
        /// <param name="responses">Array of Operation responses.</param>
        /// <param name="policies">Operation Policies</param>
        /// <param name="displayName">Operation Name.</param>
        /// <param name="method">A Valid HTTP Operation Method. Typical Http
        /// Methods like GET, PUT, POST but not limited by only them.</param>
        /// <param name="urlTemplate">Relative URL template identifying the
        /// target resource for this operation. May include parameters.
        /// Example: /customers/{cid}/orders/{oid}/?date={date}</param>
        public OperationUpdateContract(IList<ParameterContract> templateParameters = default(IList<ParameterContract>), string description = default(string), RequestContract request = default(RequestContract), IList<ResponseContract> responses = default(IList<ResponseContract>), string policies = default(string), string displayName = default(string), string method = default(string), string urlTemplate = default(string))
        {
            TemplateParameters = templateParameters;
            Description = description;
            Request = request;
            Responses = responses;
            Policies = policies;
            DisplayName = displayName;
            Method = method;
            UrlTemplate = urlTemplate;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets collection of URL template parameters.
        /// </summary>
        [JsonProperty(PropertyName = "properties.templateParameters")]
        public IList<ParameterContract> TemplateParameters { get; set; }

        /// <summary>
        /// Gets or sets description of the operation. May include HTML
        /// formatting tags.
        /// </summary>
        [JsonProperty(PropertyName = "properties.description")]
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets an entity containing request details.
        /// </summary>
        [JsonProperty(PropertyName = "properties.request")]
        public RequestContract Request { get; set; }

        /// <summary>
        /// Gets or sets array of Operation responses.
        /// </summary>
        [JsonProperty(PropertyName = "properties.responses")]
        public IList<ResponseContract> Responses { get; set; }

        /// <summary>
        /// Gets or sets operation Policies
        /// </summary>
        [JsonProperty(PropertyName = "properties.policies")]
        public string Policies { get; set; }

        /// <summary>
        /// Gets or sets operation Name.
        /// </summary>
        [JsonProperty(PropertyName = "properties.displayName")]
        public string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets a Valid HTTP Operation Method. Typical Http Methods
        /// like GET, PUT, POST but not limited by only them.
        /// </summary>
        [JsonProperty(PropertyName = "properties.method")]
        public string Method { get; set; }

        /// <summary>
        /// Gets or sets relative URL template identifying the target resource
        /// for this operation. May include parameters. Example:
        /// /customers/{cid}/orders/{oid}/?date={date}
        /// </summary>
        [JsonProperty(PropertyName = "properties.urlTemplate")]
        public string UrlTemplate { get; set; }

    }
}
