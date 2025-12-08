using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
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
                })
                .AddKeycloakOpenIdConnect(
                    serviceName: "keycloak",
                    realm: "XMasDev",
                    options =>
                    {
                        options.ClientId = "missionenataleprotetto";
                        options.ClientSecret = "1vN1VIgowcNwnWxL4ZAjeRz0JTOEP7y6";
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
                                //var scope = t.HttpContext.RequestServices.CreateScope();

                                var claimsIdentity = (ClaimsIdentity)t.Principal.Identity;

                                claimsIdentity.AddClaim(new Claim("role", "ChristmasManager"));
                                claimsIdentity.AddClaim(new Claim("role", "LetterReader"));

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
