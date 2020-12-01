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
    /// Extension methods for ApiOperation.
    /// </summary>
    public static partial class ApiOperationExtensions
    {
            /// <summary>
            /// Lists a collection of the operations for the specified API.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='filter'>
            /// |   Field     |     Usage     |     Supported operators     |     Supported
            /// functions
            /// |&lt;/br&gt;|-------------|-------------|-------------|-------------|&lt;/br&gt;|
            /// name | filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| displayName | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| method | filter
            /// | ge, le, eq, ne, gt, lt | substringof, contains, startswith, endswith |
            /// &lt;/br&gt;| description | filter | ge, le, eq, ne, gt, lt | substringof,
            /// contains, startswith, endswith | &lt;/br&gt;| urlTemplate | filter | ge,
            /// le, eq, ne, gt, lt | substringof, contains, startswith, endswith |
            /// &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='tags'>
            /// Include tags in the response.
            /// </param>
            public static OperationCollection ListByApi(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string filter = default(string), int? top = default(int?), int? skip = default(int?), string tags = default(string))
            {
                return operations.ListByApiAsync(resourceGroupName, serviceName, apiId, filter, top, skip, tags).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists a collection of the operations for the specified API.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='filter'>
            /// |   Field     |     Usage     |     Supported operators     |     Supported
            /// functions
            /// |&lt;/br&gt;|-------------|-------------|-------------|-------------|&lt;/br&gt;|
            /// name | filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| displayName | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| method | filter
            /// | ge, le, eq, ne, gt, lt | substringof, contains, startswith, endswith |
            /// &lt;/br&gt;| description | filter | ge, le, eq, ne, gt, lt | substringof,
            /// contains, startswith, endswith | &lt;/br&gt;| urlTemplate | filter | ge,
            /// le, eq, ne, gt, lt | substringof, contains, startswith, endswith |
            /// &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='tags'>
            /// Include tags in the response.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<OperationCollection> ListByApiAsync(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string filter = default(string), int? top = default(int?), int? skip = default(int?), string tags = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByApiWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, filter, top, skip, tags, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the API operation specified by its
            /// identifier.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            public static ApiOperationGetEntityTagHeaders GetEntityTag(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId)
            {
                return operations.GetEntityTagAsync(resourceGroupName, serviceName, apiId, operationId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the API operation specified by its
            /// identifier.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<ApiOperationGetEntityTagHeaders> GetEntityTagAsync(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetEntityTagWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, operationId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Headers;
                }
            }

            /// <summary>
            /// Gets the details of the API Operation specified by its identifier.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            public static OperationContract Get(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId)
            {
                return operations.GetAsync(resourceGroupName, serviceName, apiId, operationId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the details of the API Operation specified by its identifier.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<OperationContract> GetAsync(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, operationId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates a new operation in the API or updates an existing one.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='parameters'>
            /// Create parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            public static OperationContract CreateOrUpdate(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, OperationContract parameters, string ifMatch = default(string))
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, apiId, operationId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates a new operation in the API or updates an existing one.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='parameters'>
            /// Create parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<OperationContract> CreateOrUpdateAsync(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, OperationContract parameters, string ifMatch = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, operationId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Updates the details of the operation in the API specified by its
            /// identifier.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='parameters'>
            /// API Operation Update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Update(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, OperationUpdateContract parameters, string ifMatch)
            {
                operations.UpdateAsync(resourceGroupName, serviceName, apiId, operationId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates the details of the operation in the API specified by its
            /// identifier.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='parameters'>
            /// API Operation Update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task UpdateAsync(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, OperationUpdateContract parameters, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.UpdateWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, operationId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Deletes the specified operation in the API.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Delete(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, string ifMatch)
            {
                operations.DeleteAsync(resourceGroupName, serviceName, apiId, operationId, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the specified operation in the API.
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
            /// <param name='apiId'>
            /// API revision identifier. Must be unique in the current API Management
            /// service instance. Non-current revision has ;rev=n as a suffix where n is
            /// the revision number.
            /// </param>
            /// <param name='operationId'>
            /// Operation identifier within an API. Must be unique in the current API
            /// Management service instance.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IApiOperation operations, string resourceGroupName, string serviceName, string apiId, string operationId, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, operationId, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

    }
}