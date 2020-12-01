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
    /// Extension methods for Gateway.
    /// </summary>
    public static partial class GatewayExtensions
    {
            /// <summary>
            /// Lists a collection of gateways registered with service instance.
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
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            public static GatewayCollection ListByService(this IGateway operations, string resourceGroupName, string serviceName, int? top = default(int?), int? skip = default(int?))
            {
                return operations.ListByServiceAsync(resourceGroupName, serviceName, top, skip).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists a collection of gateways registered with service instance.
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
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GatewayCollection> ListByServiceAsync(this IGateway operations, string resourceGroupName, string serviceName, int? top = default(int?), int? skip = default(int?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByServiceWithHttpMessagesAsync(resourceGroupName, serviceName, top, skip, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the Gateway specified by its
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            public static GatewayGetEntityTagHeaders GetEntityTag(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId)
            {
                return operations.GetEntityTagAsync(resourceGroupName, serviceName, gatewayId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the Gateway specified by its
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GatewayGetEntityTagHeaders> GetEntityTagAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetEntityTagWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Headers;
                }
            }

            /// <summary>
            /// Gets the details of the Gateway specified by its identifier.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            public static GatewayContract Get(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId)
            {
                return operations.GetAsync(resourceGroupName, serviceName, gatewayId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the details of the Gateway specified by its identifier.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GatewayContract> GetAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates or updates a Gateway to be used in Api Management instance.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            public static GatewayContract CreateOrUpdate(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayContract parameters, string ifMatch = default(string))
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, gatewayId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or updates a Gateway to be used in Api Management instance.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GatewayContract> CreateOrUpdateAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayContract parameters, string ifMatch = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Updates the details of the gateway specified by its identifier.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Update(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayContract parameters, string ifMatch)
            {
                operations.UpdateAsync(resourceGroupName, serviceName, gatewayId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates the details of the gateway specified by its identifier.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task UpdateAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayContract parameters, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.UpdateWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Deletes specific Gateway.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Delete(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, string ifMatch)
            {
                operations.DeleteAsync(resourceGroupName, serviceName, gatewayId, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes specific Gateway.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Retrieves gateway keys.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            public static GatewayKeysContract ListKeys(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId)
            {
                return operations.ListKeysAsync(resourceGroupName, serviceName, gatewayId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Retrieves gateway keys.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GatewayKeysContract> ListKeysAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListKeysWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Regenerates specified gateway key invalidating any tokens created with it.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            public static void RegenerateKey(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayKeyRegenerationRequestContract parameters)
            {
                operations.RegenerateKeyAsync(resourceGroupName, serviceName, gatewayId, parameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Regenerates specified gateway key invalidating any tokens created with it.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task RegenerateKeyAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayKeyRegenerationRequestContract parameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.RegenerateKeyWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, parameters, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Gets the Shared Access Authorization Token for the gateway.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            public static GatewayTokenContract GenerateToken(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayTokenRequestContract parameters)
            {
                return operations.GenerateTokenAsync(resourceGroupName, serviceName, gatewayId, parameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the Shared Access Authorization Token for the gateway.
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
            /// <param name='gatewayId'>
            /// Gateway entity identifier. Must be unique in the current API Management
            /// service instance. Must not have value 'managed'
            /// </param>
            /// <param name='parameters'>
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GatewayTokenContract> GenerateTokenAsync(this IGateway operations, string resourceGroupName, string serviceName, string gatewayId, GatewayTokenRequestContract parameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GenerateTokenWithHttpMessagesAsync(resourceGroupName, serviceName, gatewayId, parameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}