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
    /// Extension methods for Logger.
    /// </summary>
    public static partial class LoggerExtensions
    {
            /// <summary>
            /// Lists a collection of loggers in the specified service instance.
            /// <see href="https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-log-event-hubs" />
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
            /// endswith | &lt;/br&gt;| description | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| loggerType |
            /// filter | eq |     | &lt;/br&gt;| resourceId | filter | ge, le, eq, ne, gt,
            /// lt | substringof, contains, startswith, endswith | &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            public static LoggerCollection ListByService(this ILogger operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?))
            {
                return operations.ListByServiceAsync(resourceGroupName, serviceName, filter, top, skip).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists a collection of loggers in the specified service instance.
            /// <see href="https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-log-event-hubs" />
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
            /// endswith | &lt;/br&gt;| description | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| loggerType |
            /// filter | eq |     | &lt;/br&gt;| resourceId | filter | ge, le, eq, ne, gt,
            /// lt | substringof, contains, startswith, endswith | &lt;/br&gt;
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
            public static async Task<LoggerCollection> ListByServiceAsync(this ILogger operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByServiceWithHttpMessagesAsync(resourceGroupName, serviceName, filter, top, skip, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the logger specified by its
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            public static LoggerGetEntityTagHeaders GetEntityTag(this ILogger operations, string resourceGroupName, string serviceName, string loggerId)
            {
                return operations.GetEntityTagAsync(resourceGroupName, serviceName, loggerId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the logger specified by its
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<LoggerGetEntityTagHeaders> GetEntityTagAsync(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetEntityTagWithHttpMessagesAsync(resourceGroupName, serviceName, loggerId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Headers;
                }
            }

            /// <summary>
            /// Gets the details of the logger specified by its identifier.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            public static LoggerContract Get(this ILogger operations, string resourceGroupName, string serviceName, string loggerId)
            {
                return operations.GetAsync(resourceGroupName, serviceName, loggerId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the details of the logger specified by its identifier.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<LoggerContract> GetAsync(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, loggerId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates or Updates a logger.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            /// <param name='parameters'>
            /// Create parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            public static LoggerContract CreateOrUpdate(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, LoggerContract parameters, string ifMatch = default(string))
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, loggerId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or Updates a logger.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
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
            public static async Task<LoggerContract> CreateOrUpdateAsync(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, LoggerContract parameters, string ifMatch = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, loggerId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Updates an existing logger.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            /// <param name='parameters'>
            /// Update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Update(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, LoggerUpdateContract parameters, string ifMatch)
            {
                operations.UpdateAsync(resourceGroupName, serviceName, loggerId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates an existing logger.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            /// <param name='parameters'>
            /// Update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task UpdateAsync(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, LoggerUpdateContract parameters, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.UpdateWithHttpMessagesAsync(resourceGroupName, serviceName, loggerId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Deletes the specified logger.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='force'>
            /// Force deletion even if diagnostic is attached.
            /// </param>
            public static void Delete(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, string ifMatch, bool? force = default(bool?))
            {
                operations.DeleteAsync(resourceGroupName, serviceName, loggerId, ifMatch, force).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the specified logger.
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
            /// <param name='loggerId'>
            /// Logger identifier. Must be unique in the API Management service instance.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='force'>
            /// Force deletion even if diagnostic is attached.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this ILogger operations, string resourceGroupName, string serviceName, string loggerId, string ifMatch, bool? force = default(bool?), CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, loggerId, ifMatch, force, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

    }
}