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
    /// Extension methods for Notification.
    /// </summary>
    public static partial class NotificationExtensions
    {
            /// <summary>
            /// Lists a collection of properties defined within a service instance.
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
            public static NotificationCollection ListByService(this INotification operations, string resourceGroupName, string serviceName, int? top = default(int?), int? skip = default(int?))
            {
                return operations.ListByServiceAsync(resourceGroupName, serviceName, top, skip).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists a collection of properties defined within a service instance.
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
            public static async Task<NotificationCollection> ListByServiceAsync(this INotification operations, string resourceGroupName, string serviceName, int? top = default(int?), int? skip = default(int?), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByServiceWithHttpMessagesAsync(resourceGroupName, serviceName, top, skip, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the details of the Notification specified by its identifier.
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
            /// <param name='notificationName'>
            /// Notification Name Identifier. Possible values include:
            /// 'RequestPublisherNotificationMessage',
            /// 'PurchasePublisherNotificationMessage',
            /// 'NewApplicationNotificationMessage', 'BCC',
            /// 'NewIssuePublisherNotificationMessage', 'AccountClosedPublisher',
            /// 'QuotaLimitApproachingPublisherNotificationMessage'
            /// </param>
            public static NotificationContract Get(this INotification operations, string resourceGroupName, string serviceName, string notificationName)
            {
                return operations.GetAsync(resourceGroupName, serviceName, notificationName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the details of the Notification specified by its identifier.
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
            /// <param name='notificationName'>
            /// Notification Name Identifier. Possible values include:
            /// 'RequestPublisherNotificationMessage',
            /// 'PurchasePublisherNotificationMessage',
            /// 'NewApplicationNotificationMessage', 'BCC',
            /// 'NewIssuePublisherNotificationMessage', 'AccountClosedPublisher',
            /// 'QuotaLimitApproachingPublisherNotificationMessage'
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<NotificationContract> GetAsync(this INotification operations, string resourceGroupName, string serviceName, string notificationName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, serviceName, notificationName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Create or Update API Management publisher notification.
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
            /// <param name='notificationName'>
            /// Notification Name Identifier. Possible values include:
            /// 'RequestPublisherNotificationMessage',
            /// 'PurchasePublisherNotificationMessage',
            /// 'NewApplicationNotificationMessage', 'BCC',
            /// 'NewIssuePublisherNotificationMessage', 'AccountClosedPublisher',
            /// 'QuotaLimitApproachingPublisherNotificationMessage'
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            public static NotificationContract CreateOrUpdate(this INotification operations, string resourceGroupName, string serviceName, string notificationName, string ifMatch = default(string))
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, notificationName, ifMatch).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Create or Update API Management publisher notification.
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
            /// <param name='notificationName'>
            /// Notification Name Identifier. Possible values include:
            /// 'RequestPublisherNotificationMessage',
            /// 'PurchasePublisherNotificationMessage',
            /// 'NewApplicationNotificationMessage', 'BCC',
            /// 'NewIssuePublisherNotificationMessage', 'AccountClosedPublisher',
            /// 'QuotaLimitApproachingPublisherNotificationMessage'
            /// </param>
            /// <param name='ifMatch'>
            /// ETag of the Entity. Not required when creating an entity, but required when
            /// updating an entity.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<NotificationContract> CreateOrUpdateAsync(this INotification operations, string resourceGroupName, string serviceName, string notificationName, string ifMatch = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, notificationName, ifMatch, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}
