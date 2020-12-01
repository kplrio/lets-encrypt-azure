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
    /// Extension methods for ProductGroup.
    /// </summary>
    public static partial class ProductGroupExtensions
    {
            /// <summary>
            /// Lists the collection of developer groups associated with the specified
            /// product.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='filter'>
            /// |   Field     |     Usage     |     Supported operators     |     Supported
            /// functions
            /// |&lt;/br&gt;|-------------|-------------|-------------|-------------|&lt;/br&gt;|
            /// name | filter | ge, le, eq, ne, gt, lt |     | &lt;/br&gt;| displayName |
            /// filter | eq, ne |     | &lt;/br&gt;| description | filter | eq, ne |     |
            /// &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            public static GroupCollection ListByProduct(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string filter = default(string), int? top = default(int?), int? skip = default(int?))
            {
                return operations.ListByProductAsync(resourceGroupName, serviceName, productId, filter, top, skip).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists the collection of developer groups associated with the specified
            /// product.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='filter'>
            /// |   Field     |     Usage     |     Supported operators     |     Supported
            /// functions
            /// |&lt;/br&gt;|-------------|-------------|-------------|-------------|&lt;/br&gt;|
            /// name | filter | ge, le, eq, ne, gt, lt |     | &lt;/br&gt;| displayName |
            /// filter | eq, ne |     | &lt;/br&gt;| description | filter | eq, ne |     |
            /// &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GroupCollection> ListByProductAsync(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string filter = default(string), int? top = default(int?), int? skip = default(int?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByProductWithHttpMessagesAsync(resourceGroupName, serviceName, productId, filter, top, skip, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Checks that Group entity specified by identifier is associated with the
            /// Product entity.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='groupId'>
            /// Group identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static void CheckEntityExists(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string groupId)
            {
                operations.CheckEntityExistsAsync(resourceGroupName, serviceName, productId, groupId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Checks that Group entity specified by identifier is associated with the
            /// Product entity.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='groupId'>
            /// Group identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task CheckEntityExistsAsync(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string groupId, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.CheckEntityExistsWithHttpMessagesAsync(resourceGroupName, serviceName, productId, groupId, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Adds the association between the specified developer group with the
            /// specified product.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='groupId'>
            /// Group identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static GroupContract CreateOrUpdate(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string groupId)
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, productId, groupId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Adds the association between the specified developer group with the
            /// specified product.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='groupId'>
            /// Group identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GroupContract> CreateOrUpdateAsync(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string groupId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, productId, groupId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Deletes the association between the specified group and product.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='groupId'>
            /// Group identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static void Delete(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string groupId)
            {
                operations.DeleteAsync(resourceGroupName, serviceName, productId, groupId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the association between the specified group and product.
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
            /// <param name='productId'>
            /// Product identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='groupId'>
            /// Group identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IProductGroup operations, string resourceGroupName, string serviceName, string productId, string groupId, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, productId, groupId, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

    }
}