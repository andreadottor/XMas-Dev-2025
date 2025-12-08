using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Routing;

internal static class IdentityComponentsEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapAdditionalIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var accountGroup = endpoints.MapGroup("/Account");

        accountGroup.MapPost("/Logout", async (
            HttpContext context,
            ClaimsPrincipal user,
            IConfiguration configuration) =>
        {
            var postLogoutRedirectUri = $"{context.Request.Scheme}://{context.Request.Host}/Account/logout-completed";

            // Recupera l'id_token dalla sessione (necessario per il logout da Keycloak)
            var idToken = await context.GetTokenAsync(OpenIdConnectDefaults.AuthenticationScheme, "id_token");

            // Costruisci l'URL di logout di Keycloak
            var keycloakBaseUrl = configuration["Oidc:Authority"];
            var logoutUri = $"{keycloakBaseUrl}/protocol/openid-connect/logout" +
                            $"?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutRedirectUri)}" +
                            (idToken != null ? $"&id_token_hint={idToken}" : "");

            // Esegui il sign-out dall'applicazione
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

            // Reindirizza a Keycloak per completare il logout
            return TypedResults.Redirect(logoutUri);
        }).DisableAntiforgery();

        return accountGroup;
    }
}
