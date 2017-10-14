/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Builder;

namespace AspNet.Security.OAuth.Adfs
{
    /// <summary>
    /// Default values used by the ADFS authentication middleware.
    /// </summary>
    public static class AdfsAuthenticationDefaults
    {
        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.AuthenticationScheme"/>.
        /// </summary>
        public const string AuthenticationScheme = "ADFS";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "ADFS";

        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "ADFS";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-adfs";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.AuthorizationEndpoint"/>.
        /// </summary>
        /// <example>
        /// https://adfs.local/adfs/oauth2/authorize
        /// </example>
        public const string AuthorizationEndpoint = "https://adfs.local/adfs/oauth2/authorize";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.TokenEndpoint"/>.
        /// </summary>
        /// <example>
        /// https://adfs.local/adfs/oauth2/token
        /// </example>
        public const string TokenEndpoint = "https://adfs.local/adfs/oauth2/token";

        /// <summary>
        /// Default value for <see cref="AdfsAuthenticationOptions.FederationServiceIdentifier"/>.
        /// </summary>
        /// <example>
        /// http://adfs.local/adfs/services/trust
        /// </example>
        public const string FederationServiceIdentifier = "http://adfs.local/adfs/services/trust";

        /// <summary>
        /// Default value for <see cref="AdfsAuthenticationOptions.UsernameClaimType"/>.
        /// </summary>
        /// 
        public const string UsernameClaimType = "winaccountname";

        /// <summary>
        /// Default value for <see cref="AdfsAuthenticationOptions.RoleClaimType"/>.
        /// </summary>
        public const string RoleClaimType = "role";
    }
}
