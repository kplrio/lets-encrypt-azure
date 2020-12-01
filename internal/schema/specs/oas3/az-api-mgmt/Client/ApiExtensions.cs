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
    /// Extension methods for Api.
    /// </summary>
    public static partial class ApiExtensions
    {
            /// <summary>
            /// Lists all APIs of the API Management service instance.
            /// <see href="https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-create-apis" />
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
            /// <param name='filter'>
            /// |   Field     |     Usage     |     Supported operators     |     Supported
            /// functions
            /// |&lt;/br&gt;|-------------|-------------|-------------|-------------|&lt;/br&gt;|
            /// name | filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| displayName | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| description |
            /// filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| serviceUrl | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| path | filter |
            /// ge, le, eq, ne, gt, lt | substringof, contains, startswith, endswith |
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
            /// <param name='expandApiVersionSet'>
            /// Include full ApiVersionSet resource in response
            /// </param>
            public static ApiCollection ListByService(this IApi operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), string tags = default(string), bool? expandApiVersionSet = default(bool?))
            {
                return operations.ListByServiceAsync(resourceGroupName, serviceName, filter, top, skip, tags, expandApiVersionSet).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists all APIs of the API Management service instance.
            /// <see href="https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-create-apis" />
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
            /// <param name='filter'>
            /// |   Field     |     Usage     |     Supported operators     |     Supported
            /// functions
            /// |&lt;/br&gt;|-------------|-------------|-------------|-------------|&lt;/br&gt;|
            /// name | filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| displayName | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| description |
            /// filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| serviceUrl | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| path | filter |
            /// ge, le, eq, ne, gt, lt | substringof, contains, startswith, endswith |
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
            /// <param name='expandApiVersionSet'>
            /// Include full ApiVersionSet resource in response
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<ApiCollection> ListByServiceAsync(this IApi operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), string tags = default(string), bool? expandApiVersionSet = default(bool?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByServiceWithHttpMessagesAsync(resourceGroupName, serviceName, filter, top, skip, tags, expandApiVersionSet, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the API specified by its
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
            public static ApiGetEntityTagHeaders GetEntityTag(this IApi operations, string resourceGroupName, string serviceName, string apiId)
            {
                return operations.GetEntityTagAsync(resourceGroupName, serviceName, apiId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the API specified by its
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
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<ApiGetEntityTagHeaders> GetEntityTagAsync(this IApi operations, string resourceGroupName, string serviceName, string apiId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetEntityTagWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Headers;
                }
            }

            /// <summary>
            /// Gets the details of the API specified by its identifier.
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
            public static ApiContract Get(this IApi operations, string resourceGroupName, string serviceName, string apiId)
            {
                return operations.GetAsync(resourceGroupName, serviceName, apiId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the details of the API specified by its identifier.
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
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<ApiContract> GetAsync(this IApi operations, string resourceGroupName, string serviceName, string apiId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates new or updates existing specified API of the API Management service
            /// instance.
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
            /// <param name='parameters'>
            /// Create or update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            public static ApiContract CreateOrUpdate(this IApi operations, string resourceGroupName, string serviceName, string apiId, ApiCreateOrUpdateParameter parameters, string ifMatch = default(string))
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, apiId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates new or updates existing specified API of the API Management service
            /// instance.
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
            /// <param name='parameters'>
            /// Create or update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<ApiContract> CreateOrUpdateAsync(this IApi operations, string resourceGroupName, string serviceName, string apiId, ApiCreateOrUpdateParameter parameters, string ifMatch = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Updates the specified API of the API Management service instance.
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
            /// <param name='parameters'>
            /// API Update Contract parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Update(this IApi operations, string resourceGroupName, string serviceName, string apiId, ApiUpdateContract parameters, string ifMatch)
            {
                operations.UpdateAsync(resourceGroupName, serviceName, apiId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates the specified API of the API Management service instance.
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
            /// <param name='parameters'>
            /// API Update Contract parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task UpdateAsync(this IApi operations, string resourceGroupName, string serviceName, string apiId, ApiUpdateContract parameters, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.UpdateWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Deletes the specified API of the API Management service instance.
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
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='deleteRevisions'>
            /// Delete all revisions of the Api.
            /// </param>
            public static void Delete(this IApi operations, string resourceGroupName, string serviceName, string apiId, string ifMatch, bool? deleteRevisions = default(bool?))
            {
                operations.DeleteAsync(resourceGroupName, serviceName, apiId, ifMatch, deleteRevisions).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the specified API of the API Management service instance.
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
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='deleteRevisions'>
            /// Delete all revisions of the Api.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IApi operations, string resourceGroupName, string serviceName, string apiId, string ifMatch, bool? deleteRevisions = default(bool?), CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, apiId, ifMatch, deleteRevisions, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Lists a collection of apis associated with tags.
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
            /// <param name='filter'>
            /// | Field       | Supported operators    | Supported functions
            /// |
            /// |-------------|------------------------|-----------------------------------|
            ///
            /// |name | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |displayName | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |apiRevision | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |path | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |description | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |serviceUrl | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |isCurrent | eq |    |
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='includeNotTaggedApis'>
            /// Include not tagged APIs.
            /// </param>
            public static TagResourceCollection ListByTags(this IApi operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), bool? includeNotTaggedApis = default(bool?))
            {
                return operations.ListByTagsAsync(resourceGroupName, serviceName, filter, top, skip, includeNotTaggedApis).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists a collection of apis associated with tags.
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
            /// <param name='filter'>
            /// | Field       | Supported operators    | Supported functions
            /// |
            /// |-------------|------------------------|-----------------------------------|
            ///
            /// |name | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |displayName | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |apiRevision | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |path | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |description | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |serviceUrl | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith|
            /// |isCurrent | eq |    |
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='includeNotTaggedApis'>
            /// Include not tagged APIs.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<TagResourceCollection> ListByTagsAsync(this IApi operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), bool? includeNotTaggedApis = default(bool?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByTagsWithHttpMessagesAsync(resourceGroupName, serviceName, filter, top, skip, includeNotTaggedApis, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}