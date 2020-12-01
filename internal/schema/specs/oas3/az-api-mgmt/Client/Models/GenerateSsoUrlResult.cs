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
    /// Generate SSO Url operations response details.
    /// </summary>
    public partial class GenerateSsoUrlResult
    {
        /// <summary>
        /// Initializes a new instance of the GenerateSsoUrlResult class.
        /// </summary>
        public GenerateSsoUrlResult()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the GenerateSsoUrlResult class.
        /// </summary>
        /// <param name="value">Redirect Url containing the SSO URL
        /// value.</param>
        public GenerateSsoUrlResult(string value = default(string))
        {
            Value = value;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets redirect Url containing the SSO URL value.
        /// </summary>
        [JsonProperty(PropertyName = "value")]
        public string Value { get; set; }

    }
}