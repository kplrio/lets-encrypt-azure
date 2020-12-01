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
    /// Extension methods for NotificationRecipientUser.
    /// </summary>
    public static partial class NotificationRecipientUserExtensions
    {
            /// <summary>
            /// Gets the list of the Notification Recipient User subscribed to the
            /// notification.
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
            public static RecipientUserCollection ListByNotification(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName)
            {
                return operations.ListByNotificationAsync(resourceGroupName, serviceName, notificationName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the list of the Notification Recipient User subscribed to the
            /// notification.
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
            public static async Task<RecipientUserCollection> ListByNotificationAsync(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByNotificationWithHttpMessagesAsync(resourceGroupName, serviceName, notificationName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Determine if the Notification Recipient User is subscribed to the
            /// notification.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static void CheckEntityExists(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName, string userId)
            {
                operations.CheckEntityExistsAsync(resourceGroupName, serviceName, notificationName, userId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Determine if the Notification Recipient User is subscribed to the
            /// notification.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task CheckEntityExistsAsync(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName, string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.CheckEntityExistsWithHttpMessagesAsync(resourceGroupName, serviceName, notificationName, userId, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Adds the API Management User to the list of Recipients for the
            /// Notification.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static RecipientUserContract CreateOrUpdate(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName, string userId)
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, serviceName, notificationName, userId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Adds the API Management User to the list of Recipients for the
            /// Notification.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<RecipientUserContract> CreateOrUpdateAsync(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName, string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, serviceName, notificationName, userId, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Removes the API Management user from the list of Notification.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            public static void Delete(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName, string userId)
            {
                operations.DeleteAsync(resourceGroupName, serviceName, notificationName, userId).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Removes the API Management user from the list of Notification.
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
            /// <param name='userId'>
            /// User identifier. Must be unique in the current API Management service
            /// instance.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this INotificationRecipientUser operations, string resourceGroupName, string serviceName, string notificationName, string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, serviceName, notificationName, userId, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

    }
}