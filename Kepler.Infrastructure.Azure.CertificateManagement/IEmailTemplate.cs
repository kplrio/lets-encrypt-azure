// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement
{
    using Microsoft.Rest;
    using Models;
    using System.Collections;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// EmailTemplate operations.
    /// </summary>
    public partial interface IEmailTemplate
    {
        /// <summary>
        /// Lists a collection of properties defined within a service instance.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the API Management service.
        /// </param>
        /// <param name='filter'>
        /// |   Field     |     Usage     |     Supported operators     |
        /// Supported functions
        /// |&lt;/br&gt;|-------------|-------------|-------------|-------------|&lt;/br&gt;|
        /// name | filter | ge, le, eq, ne, gt, lt | substringof, contains,
        /// startswith, endswith | &lt;/br&gt;
        /// </param>
        /// <param name='top'>
        /// Number of records to return.
        /// </param>
        /// <param name='skip'>
        /// Number of records to skip.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="ErrorResponseException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.SerializationException">
        /// Thrown when unable to deserialize the response
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<HttpOperationResponse<EmailTemplateCollection>> ListByServiceWithHttpMessagesAsync(string resourceGroupName, string serviceName, string filter = default(string), int? top = default(int?), int? skip = default(int?), Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Gets the entity state (Etag) version of the email template
        /// specified by its identifier.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the API Management service.
        /// </param>
        /// <param name='templateName'>
        /// Email Template Name Identifier. Possible values include:
        /// 'applicationApprovedNotificationMessage', 'accountClosedDeveloper',
        /// 'quotaLimitApproachingDeveloperNotificationMessage',
        /// 'newDeveloperNotificationMessage', 'emailChangeIdentityDefault',
        /// 'inviteUserNotificationMessage', 'newCommentNotificationMessage',
        /// 'confirmSignUpIdentityDefault', 'newIssueNotificationMessage',
        /// 'purchaseDeveloperNotificationMessage',
        /// 'passwordResetIdentityDefault',
        /// 'passwordResetByAdminNotificationMessage',
        /// 'rejectDeveloperNotificationMessage',
        /// 'requestDeveloperNotificationMessage'
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="ErrorResponseException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<HttpOperationHeaderResponse<EmailTemplateGetEntityTagHeaders>> GetEntityTagWithHttpMessagesAsync(string resourceGroupName, string serviceName, string templateName, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Gets the details of the email template specified by its identifier.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the API Management service.
        /// </param>
        /// <param name='templateName'>
        /// Email Template Name Identifier. Possible values include:
        /// 'applicationApprovedNotificationMessage', 'accountClosedDeveloper',
        /// 'quotaLimitApproachingDeveloperNotificationMessage',
        /// 'newDeveloperNotificationMessage', 'emailChangeIdentityDefault',
        /// 'inviteUserNotificationMessage', 'newCommentNotificationMessage',
        /// 'confirmSignUpIdentityDefault', 'newIssueNotificationMessage',
        /// 'purchaseDeveloperNotificationMessage',
        /// 'passwordResetIdentityDefault',
        /// 'passwordResetByAdminNotificationMessage',
        /// 'rejectDeveloperNotificationMessage',
        /// 'requestDeveloperNotificationMessage'
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="ErrorResponseException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.SerializationException">
        /// Thrown when unable to deserialize the response
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<HttpOperationResponse<EmailTemplateContract,EmailTemplateGetHeaders>> GetWithHttpMessagesAsync(string resourceGroupName, string serviceName, string templateName, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Updates an Email Template.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the API Management service.
        /// </param>
        /// <param name='templateName'>
        /// Email Template Name Identifier. Possible values include:
        /// 'applicationApprovedNotificationMessage', 'accountClosedDeveloper',
        /// 'quotaLimitApproachingDeveloperNotificationMessage',
        /// 'newDeveloperNotificationMessage', 'emailChangeIdentityDefault',
        /// 'inviteUserNotificationMessage', 'newCommentNotificationMessage',
        /// 'confirmSignUpIdentityDefault', 'newIssueNotificationMessage',
        /// 'purchaseDeveloperNotificationMessage',
        /// 'passwordResetIdentityDefault',
        /// 'passwordResetByAdminNotificationMessage',
        /// 'rejectDeveloperNotificationMessage',
        /// 'requestDeveloperNotificationMessage'
        /// </param>
        /// <param name='parameters'>
        /// Email Template update parameters.
        /// </param>
        /// <param name='ifMatch'>
        /// ETag of the Entity. Not required when creating an entity, but
        /// required when updating an entity.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="ErrorResponseException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.SerializationException">
        /// Thrown when unable to deserialize the response
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<HttpOperationResponse<EmailTemplateContract>> CreateOrUpdateWithHttpMessagesAsync(string resourceGroupName, string serviceName, string templateName, EmailTemplateUpdateParameters parameters, string ifMatch = default(string), Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Updates the specific Email Template.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the API Management service.
        /// </param>
        /// <param name='templateName'>
        /// Email Template Name Identifier. Possible values include:
        /// 'applicationApprovedNotificationMessage', 'accountClosedDeveloper',
        /// 'quotaLimitApproachingDeveloperNotificationMessage',
        /// 'newDeveloperNotificationMessage', 'emailChangeIdentityDefault',
        /// 'inviteUserNotificationMessage', 'newCommentNotificationMessage',
        /// 'confirmSignUpIdentityDefault', 'newIssueNotificationMessage',
        /// 'purchaseDeveloperNotificationMessage',
        /// 'passwordResetIdentityDefault',
        /// 'passwordResetByAdminNotificationMessage',
        /// 'rejectDeveloperNotificationMessage',
        /// 'requestDeveloperNotificationMessage'
        /// </param>
        /// <param name='parameters'>
        /// Update parameters.
        /// </param>
        /// <param name='ifMatch'>
        /// ETag of the Entity. ETag should match the current entity state from
        /// the header response of the GET request or it should be * for
        /// unconditional update.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="ErrorResponseException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<HttpOperationResponse> UpdateWithHttpMessagesAsync(string resourceGroupName, string serviceName, string templateName, EmailTemplateUpdateParameters parameters, string ifMatch, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Reset the Email Template to default template provided by the API
        /// Management service instance.
        /// </summary>
        /// <param name='resourceGroupName'>
        /// The name of the resource group.
        /// </param>
        /// <param name='serviceName'>
        /// The name of the API Management service.
        /// </param>
        /// <param name='templateName'>
        /// Email Template Name Identifier. Possible values include:
        /// 'applicationApprovedNotificationMessage', 'accountClosedDeveloper',
        /// 'quotaLimitApproachingDeveloperNotificationMessage',
        /// 'newDeveloperNotificationMessage', 'emailChangeIdentityDefault',
        /// 'inviteUserNotificationMessage', 'newCommentNotificationMessage',
        /// 'confirmSignUpIdentityDefault', 'newIssueNotificationMessage',
        /// 'purchaseDeveloperNotificationMessage',
        /// 'passwordResetIdentityDefault',
        /// 'passwordResetByAdminNotificationMessage',
        /// 'rejectDeveloperNotificationMessage',
        /// 'requestDeveloperNotificationMessage'
        /// </param>
        /// <param name='ifMatch'>
        /// ETag of the Entity. ETag should match the current entity state from
        /// the header response of the GET request or it should be * for
        /// unconditional update.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="ErrorResponseException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<HttpOperationResponse> DeleteWithHttpMessagesAsync(string resourceGroupName, string serviceName, string templateName, string ifMatch, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
    }
}