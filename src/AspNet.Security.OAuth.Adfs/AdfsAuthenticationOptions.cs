/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Adfs
{
    /// <summary>
    /// Defines a set of options used by <see cref="AdfsAuthenticationHandler"/>.
    /// </summary>
    public class AdfsAuthenticationOptions : OAuthOptions
    {
        public AdfsAuthenticationOptions()
        {
            AuthenticationScheme = AdfsAuthenticationDefaults.AuthenticationScheme;
            DisplayName = AdfsAuthenticationDefaults.DisplayName;
            ClaimsIssuer = AdfsAuthenticationDefaults.Issuer;

            CallbackPath = new PathString(AdfsAuthenticationDefaults.CallbackPath);

            AuthorizationEndpoint = AdfsAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = AdfsAuthenticationDefaults.TokenEndpoint;
            FederationServiceIdentifier = AdfsAuthenticationDefaults.FederationServiceIdentifier;
            UsernameClaimType = AdfsAuthenticationDefaults.UsernameClaimType;
            RoleClaimType = AdfsAuthenticationDefaults.RoleClaimType;
        }

        /// <summary>
        /// Gets or sets the ADFS's Federation Service Identifier.
        /// </summary>
        public string FederationServiceIdentifier { get; set; }

        /// <summary>
        /// Gets or sets the client URI as defiend in ADFS
        /// </summary>
        public string ClientUri { get; set; }

        /// <summary>
        /// Gets or sets the full path of the Token Signing Certificate File
        /// </summary>
        public string TokenSigningCertificateFile { get; set; }

        /// <summary>
        /// Gets or sets the claim type for username
        /// </summary>
        public string UsernameClaimType { get; set; }

        /// <summary>
        /// Gets or sets the claim type for roles
        /// </summary>
        public string RoleClaimType { get; set; }
    }
}
