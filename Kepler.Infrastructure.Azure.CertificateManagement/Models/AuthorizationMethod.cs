// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Apimanagement.Models
{
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;
    using System.Runtime;
    using System.Runtime.Serialization;

    /// <summary>
    /// Defines values for AuthorizationMethod.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum AuthorizationMethod
    {
        [EnumMember(Value = "HEAD")]
        HEAD,
        [EnumMember(Value = "OPTIONS")]
        OPTIONS,
        [EnumMember(Value = "TRACE")]
        TRACE,
        [EnumMember(Value = "GET")]
        GET,
        [EnumMember(Value = "POST")]
        POST,
        [EnumMember(Value = "PUT")]
        PUT,
        [EnumMember(Value = "PATCH")]
        PATCH,
        [EnumMember(Value = "DELETE")]
        DELETE
    }
    internal static class AuthorizationMethodEnumExtension
    {
        internal static string ToSerializedValue(this AuthorizationMethod? value)
        {
            return value == null ? null : ((AuthorizationMethod)value).ToSerializedValue();
        }

        internal static string ToSerializedValue(this AuthorizationMethod value)
        {
            switch( value )
            {
                case AuthorizationMethod.HEAD:
                    return "HEAD";
                case AuthorizationMethod.OPTIONS:
                    return "OPTIONS";
                case AuthorizationMethod.TRACE:
                    return "TRACE";
                case AuthorizationMethod.GET:
                    return "GET";
                case AuthorizationMethod.POST:
                    return "POST";
                case AuthorizationMethod.PUT:
                    return "PUT";
                case AuthorizationMethod.PATCH:
                    return "PATCH";
                case AuthorizationMethod.DELETE:
                    return "DELETE";
            }
            return null;
        }

        internal static AuthorizationMethod? ParseAuthorizationMethod(this string value)
        {
            switch( value )
            {
                case "HEAD":
                    return AuthorizationMethod.HEAD;
                case "OPTIONS":
                    return AuthorizationMethod.OPTIONS;
                case "TRACE":
                    return AuthorizationMethod.TRACE;
                case "GET":
                    return AuthorizationMethod.GET;
                case "POST":
                    return AuthorizationMethod.POST;
                case "PUT":
                    return AuthorizationMethod.PUT;
                case "PATCH":
                    return AuthorizationMethod.PATCH;
                case "DELETE":
                    return AuthorizationMethod.DELETE;
            }
            return null;
        }
    }
}
