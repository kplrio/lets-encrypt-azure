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
    /// Paged Issue Comment list representation.
    /// </summary>
    public partial class IssueCommentCollection
    {
        /// <summary>
        /// Initializes a new instance of the IssueCommentCollection class.
        /// </summary>
        public IssueCommentCollection()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the IssueCommentCollection class.
        /// </summary>
        /// <param name="value">Issue Comment values.</param>
        /// <param name="nextLink">Next page link if any.</param>
        public IssueCommentCollection(IList<IssueCommentContract> value = default(IList<IssueCommentContract>), string nextLink = default(string))
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
        /// Gets issue Comment values.
        /// </summary>
        [JsonProperty(PropertyName = "value")]
        public IList<IssueCommentContract> Value { get; private set; }

        /// <summary>
        /// Gets next page link if any.
        /// </summary>
        [JsonProperty(PropertyName = "nextLink")]
        public string NextLink { get; private set; }

    }
}