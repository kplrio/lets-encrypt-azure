// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement
{
    using Models;
    using System.Collections;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Extension methods for NetworkStatus.
    /// </summary>
    public static partial class NetworkStatusExtensions
    {
            /// <summary>
            /// Gets the Connectivity Status to the external resources on which the Api
            /// Management service depends from inside the Cloud Service. This also returns
            /// the DNS Servers as visible to the CloudService.
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
            public static IList<NetworkStatusContractByLocation> ListByService(this INetworkStatus operations, string resourceGroupName, string serviceName)
            {
                return operations.ListByServiceAsync(resourceGroupName, serviceName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the Connectivity Status to the external resources on which the Api
            /// Management service depends from inside the Cloud Service. This also returns
            /// the DNS Servers as visible to the CloudService.
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
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IList<NetworkStatusContractByLocation>> ListByServiceAsync(this INetworkStatus operations, string resourceGroupName, string serviceName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByServiceWithHttpMessagesAsync(resourceGroupName, serviceName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets the Connectivity Status to the external resources on which the Api
            /// Management service depends from inside the Cloud Service. This also returns
            /// the DNS Servers as visible to the CloudService.
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
            /// <param name='locationName'>
            /// Location in which the API Management service is deployed. This is one of
            /// the Azure Regions like West US, East US, South Central US.
            /// </param>
            public static NetworkStatusContract ListByLocation(this INetworkStatus operations, string resourceGroupName, string serviceName, string locationName)
            {
                return operations.ListByLocationAsync(resourceGroupName, serviceName, locationName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the Connectivity Status to the external resources on which the Api
            /// Management service depends from inside the Cloud Service. This also returns
            /// the DNS Servers as visible to the CloudService.
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
            /// <param name='locationName'>
            /// Location in which the API Management service is deployed. This is one of
            /// the Azure Regions like West US, East US, South Central US.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<NetworkStatusContract> ListByLocationAsync(this INetworkStatus operations, string resourceGroupName, string serviceName, string locationName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByLocationWithHttpMessagesAsync(resourceGroupName, serviceName, locationName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}