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
    /// Extension methods for UserIdentities.
    /// </summary>
    public static partial class UserIdentitiesExtensions
    {
            /// <summary>
            /// List of all user identities.
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
            public static UserIdentityCollection List(this IUserIdentities operations, string resourceGroupName, string serviceName, string userId)
            {
                return operations.ListAsync(resourceGroupName, serviceName, userId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// List of all user identities.
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
            public static async Task<UserIdentityCollection> ListAsync(this IUserIdentities operations, string resourceGroupName, string serviceName, string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListWithHttpMessagesAsync(resourceGroupName, serviceName, userId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}
