/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.Adfs
{
    public class AdfsAuthenticationHandler : OAuthHandler<AdfsAuthenticationOptions>
    {
        public AdfsAuthenticationHandler([NotNull] HttpClient client)
            : base(client) {
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync([NotNull] ClaimsIdentity identity,
            [NotNull] AuthenticationProperties properties, [NotNull] OAuthTokenResponse tokens) {
            var signingCert = new X509Certificate2(Options.TokenSigningCertificateFile);

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new X509SecurityKey(signingCert),
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidAudience = Options.ClientUri,
                ValidIssuer = Options.FederationServiceIdentifier,
                RequireSignedTokens = true
            };

            SecurityToken securityToken;
            jwtSecurityTokenHandler.ValidateToken(tokens.AccessToken, validationParameters, out securityToken);
            identity = new ClaimsIdentity(
                ((JwtSecurityToken)securityToken).Claims,
                Options.AuthenticationScheme,
                Options.UsernameClaimType,
                Options.RoleClaimType);

            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Options.AuthenticationScheme);
            var context = new OAuthCreatingTicketContext(ticket, Context, Options, Backchannel, tokens);

            await Options.Events.CreatingTicket(context);

            return context.Ticket;
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var scope = FormatScope();

            var state = Options.StateDataFormat.Protect(properties);

            var queryBuilder = new QueryBuilder()
            {
                { "client_id", Options.ClientId },
                { "scope", scope },
                { "response_type", "code" },
                { "redirect_uri", redirectUri },
                { "state", state },
                { "resource", Options.ClientUri }
            };
            return Options.AuthorizationEndpoint + queryBuilder.ToString();
        }
    }
}
