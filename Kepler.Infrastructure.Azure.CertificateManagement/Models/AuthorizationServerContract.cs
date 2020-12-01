// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement.Models
{
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// External OAuth authorization server settings.
    /// </summary>
    [JsonTransformation]
    public partial class AuthorizationServerContract : Resource
    {
        /// <summary>
        /// Initializes a new instance of the AuthorizationServerContract
        /// class.
        /// </summary>
        public AuthorizationServerContract()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the AuthorizationServerContract
        /// class.
        /// </summary>
        /// <param name="displayName">User-friendly authorization server
        /// name.</param>
        /// <param name="clientRegistrationEndpoint">Optional reference to a
        /// page where client or app registration for this authorization server
        /// is performed. Contains absolute URL to entity being
        /// referenced.</param>
        /// <param name="authorizationEndpoint">OAuth authorization endpoint.
        /// See http://tools.ietf.org/html/rfc6749#section-3.2.</param>
        /// <param name="grantTypes">Form of an authorization grant, which the
        /// client uses to request the access token.</param>
        /// <param name="clientId">Client or app id registered with this
        /// authorization server.</param>
        /// <param name="id">Resource ID.</param>
        /// <param name="name">Resource name.</param>
        /// <param name="type">Resource type for API Management
        /// resource.</param>
        /// <param name="description">Description of the authorization server.
        /// Can contain HTML formatting tags.</param>
        /// <param name="authorizationMethods">HTTP verbs supported by the
        /// authorization endpoint. GET must be always present. POST is
        /// optional.</param>
        /// <param name="clientAuthenticationMethod">Method of authentication
        /// supported by the token endpoint of this authorization server.
        /// Possible values are Basic and/or Body. When Body is specified,
        /// client credentials and other parameters are passed within the
        /// request body in the application/x-www-form-urlencoded
        /// format.</param>
        /// <param name="tokenBodyParameters">Additional parameters required by
        /// the token endpoint of this authorization server represented as an
        /// array of JSON objects with name and value string properties, i.e.
        /// {"name" : "name value", "value": "a value"}.</param>
        /// <param name="tokenEndpoint">OAuth token endpoint. Contains absolute
        /// URI to entity being referenced.</param>
        /// <param name="supportState">If true, authorization server will
        /// include state parameter from the authorization request to its
        /// response. Client may use state parameter to raise protocol
        /// security.</param>
        /// <param name="defaultScope">Access token scope that is going to be
        /// requested by default. Can be overridden at the API level. Should be
        /// provided in the form of a string containing space-delimited
        /// values.</param>
        /// <param name="bearerTokenSendingMethods">Specifies the mechanism by
        /// which access token is passed to the API. </param>
        /// <param name="resourceOwnerUsername">Can be optionally specified
        /// when resource owner password grant type is supported by this
        /// authorization server. Default resource owner username.</param>
        /// <param name="resourceOwnerPassword">Can be optionally specified
        /// when resource owner password grant type is supported by this
        /// authorization server. Default resource owner password.</param>
        /// <param name="clientSecret">Client or app secret registered with
        /// this authorization server. This property will not be filled on
        /// 'GET' operations! Use '/listSecrets' POST request to get the
        /// value.</param>
        public AuthorizationServerContract(string displayName, string clientRegistrationEndpoint, string authorizationEndpoint, IList<string> grantTypes, string clientId, string id = default(string), string name = default(string), string type = default(string), string description = default(string), IList<AuthorizationMethod?> authorizationMethods = default(IList<AuthorizationMethod?>), IList<string> clientAuthenticationMethod = default(IList<string>), IList<TokenBodyParameterContract> tokenBodyParameters = default(IList<TokenBodyParameterContract>), string tokenEndpoint = default(string), bool? supportState = default(bool?), string defaultScope = default(string), IList<string> bearerTokenSendingMethods = default(IList<string>), string resourceOwnerUsername = default(string), string resourceOwnerPassword = default(string), string clientSecret = default(string))
            : base(id, name, type)
        {
            Description = description;
            AuthorizationMethods = authorizationMethods;
            ClientAuthenticationMethod = clientAuthenticationMethod;
            TokenBodyParameters = tokenBodyParameters;
            TokenEndpoint = tokenEndpoint;
            SupportState = supportState;
            DefaultScope = defaultScope;
            BearerTokenSendingMethods = bearerTokenSendingMethods;
            ResourceOwnerUsername = resourceOwnerUsername;
            ResourceOwnerPassword = resourceOwnerPassword;
            DisplayName = displayName;
            ClientRegistrationEndpoint = clientRegistrationEndpoint;
            AuthorizationEndpoint = authorizationEndpoint;
            GrantTypes = grantTypes;
            ClientId = clientId;
            ClientSecret = clientSecret;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets description of the authorization server. Can contain
        /// HTML formatting tags.
        /// </summary>
        [JsonProperty(PropertyName = "properties.description")]
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets HTTP verbs supported by the authorization endpoint.
        /// GET must be always present. POST is optional.
        /// </summary>
        [JsonProperty(PropertyName = "properties.authorizationMethods")]
        public IList<AuthorizationMethod?> AuthorizationMethods { get; set; }

        /// <summary>
        /// Gets or sets method of authentication supported by the token
        /// endpoint of this authorization server. Possible values are Basic
        /// and/or Body. When Body is specified, client credentials and other
        /// parameters are passed within the request body in the
        /// application/x-www-form-urlencoded format.
        /// </summary>
        [JsonProperty(PropertyName = "properties.clientAuthenticationMethod")]
        public IList<string> ClientAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets or sets additional parameters required by the token endpoint
        /// of this authorization server represented as an array of JSON
        /// objects with name and value string properties, i.e. {"name" : "name
        /// value", "value": "a value"}.
        /// </summary>
        [JsonProperty(PropertyName = "properties.tokenBodyParameters")]
        public IList<TokenBodyParameterContract> TokenBodyParameters { get; set; }

        /// <summary>
        /// Gets or sets oAuth token endpoint. Contains absolute URI to entity
        /// being referenced.
        /// </summary>
        [JsonProperty(PropertyName = "properties.tokenEndpoint")]
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets if true, authorization server will include state
        /// parameter from the authorization request to its response. Client
        /// may use state parameter to raise protocol security.
        /// </summary>
        [JsonProperty(PropertyName = "properties.supportState")]
        public bool? SupportState { get; set; }

        /// <summary>
        /// Gets or sets access token scope that is going to be requested by
        /// default. Can be overridden at the API level. Should be provided in
        /// the form of a string containing space-delimited values.
        /// </summary>
        [JsonProperty(PropertyName = "properties.defaultScope")]
        public string DefaultScope { get; set; }

        /// <summary>
        /// Gets or sets specifies the mechanism by which access token is
        /// passed to the API.
        /// </summary>
        [JsonProperty(PropertyName = "properties.bearerTokenSendingMethods")]
        public IList<string> BearerTokenSendingMethods { get; set; }

        /// <summary>
        /// Gets or sets can be optionally specified when resource owner
        /// password grant type is supported by this authorization server.
        /// Default resource owner username.
        /// </summary>
        [JsonProperty(PropertyName = "properties.resourceOwnerUsername")]
        public string ResourceOwnerUsername { get; set; }

        /// <summary>
        /// Gets or sets can be optionally specified when resource owner
        /// password grant type is supported by this authorization server.
        /// Default resource owner password.
        /// </summary>
        [JsonProperty(PropertyName = "properties.resourceOwnerPassword")]
        public string ResourceOwnerPassword { get; set; }

        /// <summary>
        /// Gets or sets user-friendly authorization server name.
        /// </summary>
        [JsonProperty(PropertyName = "properties.displayName")]
        public string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets optional reference to a page where client or app
        /// registration for this authorization server is performed. Contains
        /// absolute URL to entity being referenced.
        /// </summary>
        [JsonProperty(PropertyName = "properties.clientRegistrationEndpoint")]
        public string ClientRegistrationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets oAuth authorization endpoint. See
        /// http://tools.ietf.org/html/rfc6749#section-3.2.
        /// </summary>
        [JsonProperty(PropertyName = "properties.authorizationEndpoint")]
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets form of an authorization grant, which the client uses
        /// to request the access token.
        /// </summary>
        [JsonProperty(PropertyName = "properties.grantTypes")]
        public IList<string> GrantTypes { get; set; }

        /// <summary>
        /// Gets or sets client or app id registered with this authorization
        /// server.
        /// </summary>
        [JsonProperty(PropertyName = "properties.clientId")]
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets client or app secret registered with this
        /// authorization server. This property will not be filled on 'GET'
        /// operations! Use '/listSecrets' POST request to get the value.
        /// </summary>
        [JsonProperty(PropertyName = "properties.clientSecret")]
        public string ClientSecret { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (DisplayName == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "DisplayName");
            }
            if (ClientRegistrationEndpoint == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "ClientRegistrationEndpoint");
            }
            if (AuthorizationEndpoint == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "AuthorizationEndpoint");
            }
            if (GrantTypes == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "GrantTypes");
            }
            if (ClientId == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "ClientId");
            }
            if (TokenBodyParameters != null)
            {
                foreach (var element in TokenBodyParameters)
                {
                    if (element != null)
                    {
                        element.Validate();
                    }
                }
            }
        }
    }
}
