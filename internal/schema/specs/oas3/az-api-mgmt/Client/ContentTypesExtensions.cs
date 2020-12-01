// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement
{
    using Models;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Extension methods for ContentTypes.
    /// </summary>
    public static partial class ContentTypesExtensions
    {
            /// <summary>
            /// Gets API Management content type details
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='serviceName'>
            /// The name of the API Management service.
            /// </param>
            /// <param name='contentTypeId'>
            /// Content type identifier.
            /// </param>
            public static ContentTypeContract Get(this IContentTypes operations, string resourceGroupName, string serviceName, string contentTypeId)
            {
                return operations.GetAsync(resourceGroupName, serviceName, contentTypeId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets API Management content type details
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='serviceName'>
            /// The name of the API Management service.
            /// </param>
            /// <param name='contentTypeId'>
            /// Content type identifier.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<ContentTypeContract> GetAsync(this IContentTypes operations, string resourceGroupName, string serviceName, string contentTypeId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, contentTypeId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}