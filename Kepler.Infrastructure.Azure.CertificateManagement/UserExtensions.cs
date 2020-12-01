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
    /// Extension methods for User.
    /// </summary>
    public static partial class UserExtensions
    {
            /// <summary>
            /// Lists a collection of registered users in the specified service instance.
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
            /// endswith | &lt;/br&gt;| firstName | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| lastName |
            /// filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| email | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| state | filter |
            /// eq |     | &lt;/br&gt;| registrationDate | filter | ge, le, eq, ne, gt, lt
            /// |     | &lt;/br&gt;| note | filter | ge, le, eq, ne, gt, lt | substringof,
            /// contains, startswith, endswith | &lt;/br&gt;| groups | expand |     |     |
            /// &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='expandGroups'>
            /// Detailed Group in response.
            /// </param>
            public static UserCollection ListByService(this IUser operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), bool? expandGroups = default(bool?))
            {
                return operations.ListByServiceAsync(resourceGroupName, serviceName, filter, top, skip, expandGroups).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists a collection of registered users in the specified service instance.
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
            /// endswith | &lt;/br&gt;| firstName | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| lastName |
            /// filter | ge, le, eq, ne, gt, lt | substringof, contains, startswith,
            /// endswith | &lt;/br&gt;| email | filter | ge, le, eq, ne, gt, lt |
            /// substringof, contains, startswith, endswith | &lt;/br&gt;| state | filter |
            /// eq |     | &lt;/br&gt;| registrationDate | filter | ge, le, eq, ne, gt, lt
            /// |     | &lt;/br&gt;| note | filter | ge, le, eq, ne, gt, lt | substringof,
            /// contains, startswith, endswith | &lt;/br&gt;| groups | expand |     |     |
            /// &lt;/br&gt;
            /// </param>
            /// <param name='top'>
            /// Number of records to return.
            /// </param>
            /// <param name='skip'>
            /// Number of records to skip.
            /// </param>
            /// <param name='expandGroups'>
            /// Detailed Group in response.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<UserCollection> ListByServiceAsync(this IUser operations, string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), bool? expandGroups = default(bool?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByServiceWithHttpMessagesAsync(resourceGroupName, serviceName, filter, top, skip, expandGroups, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the user specified by its
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static UserGetEntityTagHeaders GetEntityTag(this IUser operations, string resourceGroupName, string serviceName, string userId)
            {
                return operations.GetEntityTagAsync(resourceGroupName, serviceName, userId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the entity state (Etag) version of the user specified by its
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<UserGetEntityTagHeaders> GetEntityTagAsync(this IUser operations, string resourceGroupName, string serviceName, string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetEntityTagWithHttpMessagesAsync(resourceGroupName, serviceName, userId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Headers;
                }
            }

            /// <summary>
            /// Gets the details of the user specified by its identifier.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static UserContract Get(this IUser operations, string resourceGroupName, string serviceName, string userId)
            {
                return operations.GetAsync(resourceGroupName, serviceName, userId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the details of the user specified by its identifier.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<UserContract> GetAsync(this IUser operations, string resourceGroupName, string serviceName, string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, userId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates or Updates a user.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='parameters'>
            /// Create or update parameters.
            /// </param>
            /// <param name='notify'>
            /// Send an Email notification to the User.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            public static UserContract CreateOrUpdate(this IUser operations, string resourceGroupName, string serviceName, string userId, UserCreateParameters parameters, bool? notify = default(bool?), string ifMatch = default(string))
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, userId, parameters, notify, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or Updates a user.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='parameters'>
            /// Create or update parameters.
            /// </param>
            /// <param name='notify'>
            /// Send an Email notification to the User.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<UserContract> CreateOrUpdateAsync(this IUser operations, string resourceGroupName, string serviceName, string userId, UserCreateParameters parameters, bool? notify = default(bool?), string ifMatch = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, userId, parameters, notify, ifMatch, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Updates the details of the user specified by its identifier.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='parameters'>
            /// Update parameters.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            public static void Update(this IUser operations, string resourceGroupName, string serviceName, string userId, UserUpdateParameters parameters, string ifMatch)
            {
                operations.UpdateAsync(resourceGroupName, serviceName, userId, parameters, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates the details of the user specified by its identifier.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
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
            public static async Task UpdateAsync(this IUser operations, string resourceGroupName, string serviceName, string userId, UserUpdateParameters parameters, string ifMatch, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.UpdateWithHttpMessagesAsync(resourceGroupName, serviceName, userId, parameters, ifMatch, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Deletes specific user.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='deleteSubscriptions'>
            /// Whether to delete user's subscription or not.
            /// </param>
            /// <param name='notify'>
            /// Send an Account Closed Email notification to the User.
            /// </param>
            /// <param name='appType'>
            /// Determines the type of application which send the create user request.
            /// Default is legacy publisher portal. Possible values include: 'portal',
            /// 'developerPortal'
            /// </param>
            public static void Delete(this IUser operations, string resourceGroupName, string serviceName, string userId, string ifMatch, bool? deleteSubscriptions = default(bool?), bool? notify = default(bool?), string appType = default(string))
            {
                operations.DeleteAsync(resourceGroupName, serviceName, userId, ifMatch, deleteSubscriptions, notify, appType).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes specific user.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. ETag should match the current entity state from the
            /// header response of the GET request or it should be * for unconditional
            /// update.
            /// </param>
            /// <param name='deleteSubscriptions'>
            /// Whether to delete user's subscription or not.
            /// </param>
            /// <param name='notify'>
            /// Send an Account Closed Email notification to the User.
            /// </param>
            /// <param name='appType'>
            /// Determines the type of application which send the create user request.
            /// Default is legacy publisher portal. Possible values include: 'portal',
            /// 'developerPortal'
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IUser operations, string resourceGroupName, string serviceName, string userId, string ifMatch, bool? deleteSubscriptions = default(bool?), bool? notify = default(bool?), string appType = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, userId, ifMatch, deleteSubscriptions, notify, appType, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Retrieves a redirection URL containing an authentication token for signing
            /// a given user into the developer portal.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static GenerateSsoUrlResult GenerateSsoUrl(this IUser operations, string resourceGroupName, string serviceName, string userId)
            {
                return operations.GenerateSsoUrlAsync(resourceGroupName, serviceName, userId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Retrieves a redirection URL containing an authentication token for signing
            /// a given user into the developer portal.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<GenerateSsoUrlResult> GenerateSsoUrlAsync(this IUser operations, string resourceGroupName, string serviceName, string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GenerateSsoUrlWithHttpMessagesAsync(resourceGroupName, serviceName, userId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the Shared Access Authorization Token for the User.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='parameters'>
            /// Create Authorization Token parameters.
            /// </param>
            public static UserTokenResult GetSharedAccessToken(this IUser operations, string resourceGroupName, string serviceName, string userId, UserTokenParameters parameters)
            {
                return operations.GetSharedAccessTokenAsync(resourceGroupName, serviceName, userId, parameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the Shared Access Authorization Token for the User.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='parameters'>
            /// Create Authorization Token parameters.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<UserTokenResult> GetSharedAccessTokenAsync(this IUser operations, string resourceGroupName, string serviceName, string userId, UserTokenParameters parameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetSharedAccessTokenWithHttpMessagesAsync(resourceGroupName, serviceName, userId, parameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}