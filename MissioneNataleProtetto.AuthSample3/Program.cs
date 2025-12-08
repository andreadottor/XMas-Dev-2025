using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using MissioneNataleProtetto.AuthSample3;
using MissioneNataleProtetto.AuthSample3.Components;
using MissioneNataleProtetto.AuthSample3.Components.Account;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityRedirectManager>();

var clientId = builder.Configuration["Oidc:ClientId"];
var clientSecret = builder.Configuration["Oidc:ClientSecret"];

builder.Services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddCookie(options =>
                {
                    options.Cookie.IsEssential = true;
                    options.Cookie.SameSite = SameSiteMode.Lax;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    options.Cookie.HttpOnly = true;
                    options.LoginPath = string.Empty;
                    options.LogoutPath = "/account/logout";
                    options.Events = new CookieAuthenticationEvents()
                    {
                        OnValidatePrincipal = async context =>
                        {
                            // https://auth0.com/blog/exploring-auth0-aspnet-core-authentication-sdk/
                            if (context.Properties.Items.TryGetValue(".Token.access_token", out string? accessToken))
                            {
                                if (context.Properties.Items.TryGetValue(".Token.refresh_token", out string? refreshToken))
                                {
                                    // this event is fired everytime the cookie has been validated by the cookie middleware, so basically during every authenticated request.
                                    // the decryption of the cookie has already happened so we have access to the identity + user claims
                                    // and cookie properties - expiration, etc..
                                    // source: https://github.com/mderriey/aspnet-core-token-renewal/blob/2fd9abcc2abe92df2b6c4374ad3f2ce585b6f953/src/MvcClient/Startup.cs#L57
                                    var now = DateTimeOffset.UtcNow;
                                    var exp = context.Properties.ExpiresUtc.GetValueOrDefault().ToUnixTimeSeconds();
                                    var expiresAt = DateTimeOffset.Parse(context.Properties.Items[".Token.expires_at"]!);
                                    var expiresAtUnixSeconds = DateTimeOffset.Parse(context.Properties.Items[".Token.expires_at"]!).ToUnixTimeSeconds();

                                    var leeway = 120;
                                    var difference = DateTimeOffset.Compare(expiresAt, now.AddSeconds(leeway));
                                    var isExpired = difference <= 0;

                                    if (isExpired && !string.IsNullOrWhiteSpace(refreshToken)) // session cookie expired?
                                    {
                                        var keycloakServiceClient = context.HttpContext.RequestServices.GetRequiredService<HttpClient>();

                                        var response = await keycloakServiceClient.RequestRefreshTokenAsync(new RefreshTokenRequest
                                        {
                                            Address      = "https+http://keycloak/realms/XMasDev/protocol/openid-connect/token",
                                            ClientId     = clientId!,
                                            ClientSecret = clientSecret,
                                            RefreshToken = refreshToken
                                        }).ConfigureAwait(false);

                                        if (!response.IsError)
                                        {
                                            var expiresIn = DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn);
                                            var validTo = ((DateTimeOffset)new JwtSecurityToken(response.AccessToken).ValidTo);

                                            context.Properties.UpdateTokenValue("access_token", response.AccessToken!);
                                            context.Properties.UpdateTokenValue("refresh_token", response.RefreshToken!);
                                            context.Properties.UpdateTokenValue("id_token", response.IdentityToken!);
                                            context.Properties.UpdateTokenValue("expires_at", validTo.ToString("o"));
                                            context.Properties.ExpiresUtc = validTo;
                                            context.ShouldRenew = true;
                                        }
                                        else
                                        {
                                            context.RejectPrincipal();
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    };
                })
                .AddKeycloakOpenIdConnect(
                    serviceName: "keycloak",
                    realm: "XMasDev",
                    options =>
                    {
                        options.ClientId = clientId;
                        options.ClientSecret = clientSecret;
                        options.ResponseType = OpenIdConnectResponseType.Code;
                        options.SignedOutRedirectUri = "/account/logout-completed";

                        //options.Scope.Add("store:all");
                        options.GetClaimsFromUserInfoEndpoint = true;
                        options.RequireHttpsMetadata = false;
                        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        options.SaveTokens = true;
                        options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Require;

                        options.Scope.Clear();
                        options.Scope.Add("openid");
                        options.Scope.Add("profile");
                        options.Scope.Add("email");
                        options.Scope.Add("offline_access");

                        options.Events = new OpenIdConnectEvents
                        {
                            OnTokenValidated = t =>
                            {
                                var claimsIdentity = (ClaimsIdentity)t.Principal!.Identity!;

                                // TODO: Retrieve custom claims
                                claimsIdentity.AddClaim(new Claim("role", "ChristmasManager"));
                                claimsIdentity.AddClaim(new Claim("role", "LetterReader"));

                                // TODO: Upsert the user in the application database

                                t.Properties!.ExpiresUtc = new JwtSecurityToken(t.TokenEndpointResponse!.AccessToken).ValidTo; // align expiration of the cookie with expiration of the access token
                                t.Properties.IsPersistent = false;

                                return Task.CompletedTask;
                            },
                            OnSignedOutCallbackRedirect = context =>
                            {
                                context.Response.Redirect(context.Options.SignedOutRedirectUri);
                                context.HandleResponse();

                                return Task.CompletedTask;
                            },
                        };
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            NameClaimType = "preferred_username",
                            RoleClaimType = "role",
                            ValidateIssuer = true
                        };
                    });

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.MapDefaultEndpoints();

app.Run();
