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
    /// Extension methods for OpenIdConnectProvider.
    /// </summary>
    public static partial class OpenIdConnectProviderExtensions
    {
            /// <summary>
            /// Lists of all the OpenId Connect Providers.
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
            /// substringof, contains, startswith, endswith | &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            public static OpenIdConnectProviderCollection ListByService(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?))
            {
                return operations.ListByServiceAsync(resourceGroupName, serviceName, filter, top, skip).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists of all the OpenId Connect Providers.
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
            /// substringof, contains, startswith, endswith | &lt;/br&gt;
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
            public static async Task<OpenIdConnectProviderCollection> ListByServiceAsync(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByServiceWithHttpMessagesAsync(resourceGroupName, serviceName, filter, top, skip, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the openIdConnectProvider specified
            /// by its identifier.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            public static OpenIdConnectProviderGetEntityTagHeaders GetEntityTag(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid)
            {
                return operations.GetEntityTagAsync(resourceGroupName, serviceName, opid).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the openIdConnectProvider specified
            /// by its identifier.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<OpenIdConnectProviderGetEntityTagHeaders> GetEntityTagAsync(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetEntityTagWithHttpMessagesAsync(resourceGroupName, serviceName, opid, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Headers;
                }
            }

            /// <summary>
            /// Gets specific OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            public static OpenidConnectProviderContract Get(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid)
            {
                return operations.GetAsync(resourceGroupName, serviceName, opid).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets specific OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<OpenidConnectProviderContract> GetAsync(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, opid, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates or updates the OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            /// <param name='parameters'>
            /// Create parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            public static OpenidConnectProviderContract CreateOrUpdate(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, OpenidConnectProviderContract parameters, string ifMatch = default(string))
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, opid, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or updates the OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
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
            public static async Task<OpenidConnectProviderContract> CreateOrUpdateAsync(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, OpenidConnectProviderContract parameters, string ifMatch = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, opid, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Updates the specific OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            /// <param name='parameters'>
            /// Update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Update(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, OpenidConnectProviderUpdateContract parameters, string ifMatch)
            {
                operations.UpdateAsync(resourceGroupName, serviceName, opid, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates the specific OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
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
            public static async Task UpdateAsync(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, OpenidConnectProviderUpdateContract parameters, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.UpdateWithHttpMessagesAsync(resourceGroupName, serviceName, opid, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Deletes specific OpenID Connect Provider of the API Management service
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Delete(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, string ifMatch)
            {
                operations.DeleteAsync(resourceGroupName, serviceName, opid, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes specific OpenID Connect Provider of the API Management service
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, opid, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Gets the client secret details of the OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            public static ClientSecretContract ListSecrets(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid)
            {
                return operations.ListSecretsAsync(resourceGroupName, serviceName, opid).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the client secret details of the OpenID Connect Provider.
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
            /// <param name='opid'>
            /// Identifier of the OpenID Connect Provider.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<ClientSecretContract> ListSecretsAsync(this IOpenIdConnectProvider operations, string resourceGroupName, string serviceName, string opid, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListSecretsWithHttpMessagesAsync(resourceGroupName, serviceName, opid, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}