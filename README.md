# Openid 101
This simple sample project was created to walk through some OpenID Connect and ASP.Net Core concepts. Use the steps below to create a demo or just clone the repo.

## First steps
dotnet new razor -o [websitename]
dotnet run

This should launch your app on localhost:5000

## Adding the OpenID Connect support
For this I am using Auth0, but any compliant IDP should work roughly the same. Follow the quick start sample instructions, sections repeated here for completeness.

Create an application in the management portal, and give it a name and choose asp.net core 2 web as the type.

### The call back url
Following the instructions on the portal:

You will need to add this URL to the list of Allowed URLs for your application. The Callback URL for the seed project is http://localhost:60856/signin-auth0 if you use IIS Express, or http://localhost:5000/signin-auth0 if you use Kestrel, so be sure to add this to the Allowed Callback URLs section of your application.

### Configure JSON Web Token Signature Algorithm
The ASP.NET Core OpenID Connect (OIDC) middleware which will be used to authenticate the user, requires that the JSON Web Token (JWT) be signed with an asymmetric key. To configure this go to the settings for your application in the Auth0 Dashboard, scroll down and click on Show Advanced Settings. Go to the OAuth tab and set the JsonWebToken Signature Algorithm to RS256.

Note: The project should have a ref to Microsoft.AspNetCore.All in the csproj file, so we don't need the NugGet packages.

## Configure OpenID Connect Middleware
Configure services looks like this:
```cs
// This method gets called by the runtime. Use this method to add services to the container.
public void ConfigureServices(IServiceCollection services)
{
    services.AddMvc();
}
```
We need to plug in the OIDC middleware. To add the authentication services, call the AddAuthentication method. 
```cs
                // Add authentication services
                services.AddAuthentication(options => {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
```
To enable cookie authentication, call the AddCookie method.
```cs
                .AddCookie()
```
Next, configure the OIDC authentication handler. Add a call to AddOpenIdConnect. To configure the authentication scheme, pass "Auth0" as the authenticationScheme parameter. You will use this value later to challenge the OIDC middleware.
```cs
.AddOpenIdConnect("Auth0", options => {
        // Set the authority to your Auth0 domain
        options.Authority = $"https://{Configuration["Auth0:Domain"]}";
```
Configure other parameters, such as ClientId, ClientSecret or ResponseType.
```cs
        // Configure the Auth0 Client ID and Client Secret
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];

        // Set response type to code
        options.ResponseType = "code";
```
Configure the scope
```cs
        // Configure the scope
        options.Scope.Clear();
        options.Scope.Add("openid");
```
Set the callback path
```cs
        // Set the callback path, so Auth0 will call back to http://localhost:5000/signin-auth0 
        // Also ensure that you have added the URL as an Allowed Callback URL in your Auth0 dashboard 
        options.CallbackPath = new PathString("/signin-auth0");
```
Configure the Claims Issuer to be Auth0
```cs
        options.ClaimsIssuer = "Auth0";
```
Add the OpenID events
```cs
options.Events = new OpenIdConnectEvents
        {
            // handle the logout redirection 
            OnRedirectToIdentityProviderForSignOut = (context) =>
            {
                var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";

                var postLogoutUri = context.Properties.RedirectUri;
                if (!string.IsNullOrEmpty(postLogoutUri))
                {
                    if (postLogoutUri.StartsWith("/"))
                    {
                        // transform to absolute
                        var request = context.Request;
                        postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                    }
                    logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                }

                context.Response.Redirect(logoutUri);
                context.HandleResponse();

                return Task.CompletedTask;
            }
        };   
    });
```
Next, add the authentication middleware. In the Configure method of the Startup class, call the UseAuthentication method (before the mvc routes method call)

```cs
app.UseAuthentication();
```
You may need to add the following using statements:
```cs
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
```
Update your code with your applications Domain, ClientId and Client secret from the application settings screen. Add the following to the appsettings.json file
```json
  "Auth0": {
    "Domain": "{your domain}",
    "ClientId": "{your clientId}",
    "ClientSecret": "{your clientSecret}",
    "ApiIdentifier": "{your api identifier}"
  }
```
Add the login/out buttons to _layout.cshtml as a new list in the NavBar
```html
<div class="navbar-collapse collapse">
                <ul class="nav navbar-nav">
                    <li><a asp-page="/Index">Home</a></li>
                    <li><a asp-page="/About">About</a></li>
                    <li><a asp-page="/Contact">Contact</a></li>
                </ul>
                <ul class="nav navbar-nav navbar-right">
                @if (User.Identity.IsAuthenticated)
                {
                    <li><a  asp-controller="Account" asp-action="Logout">Logout</a></li>
                }
                else
                {
                    <li><a asp-controller="Account" asp-action="Login">Login</a></li>
                }
            </ul>
            </div>
```
Add a controller and the login/out methods

Add a new folder in your Razor app called controllers
Add an AccountController.cs
```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace OpenIdClientWeb.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {

        public async Task Login(string returnUrl = "/")
        {
            await HttpContext.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = returnUrl });
        }

        [Authorize]
        public async Task Logout()
        {
            await HttpContext.SignOutAsync("Auth0", new AuthenticationProperties
            {
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be whitelisted in the 
                // **Allowed Logout URLs** settings for the app.
                RedirectUri = Url.Action("Index", "Home")
            });
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
```
###Viewing the claims
Add another action to the account controller
```cs
                /// <summary>
        /// This is just a helper action to enable you to easily see all claims related to a user. It helps when debugging your
        /// application to see the in claims populated from the Auth0 ID Token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Claims()
        {
            return View();
        }
```
And a corresponding view under Views/Account called Claims.cshtml
```html
<div class="row">
    <div class="col-md-12">

        <h3>Claims associated with current User</h3>
        <p>This page displays all the claims associated the the current User. This is useful when debugging to see which claims are being populated from the Auth0 ID Token.</p>

        <table class="table">
            <thead>
            <tr>
                <th>
                    Claim
                </th>
                <th>
                    Value
                </th>
            </tr>
            </thead>
            <tbody>
            @foreach (var claim in User.Claims)
            {
                <tr>
                    <td>@claim.Type</td>
                    <td>@claim.Value</td>
                </tr>
            }
            </tbody>
        </table>
    </div>
</div>
```
Add a link to the controller action on the layout page
```HTML
                @if (User.Identity.IsAuthenticated)
                {
                    <li><a  asp-controller="Account" asp-action="Logout">Logout</a></li>
                    <li><a  asp-controller="Account" asp-action="Claims">Logout</a></li>
                }
```
Its worth a look at this link https://jwt.io/introduction/ to learn more about jwts.

###Adding a custom scope
The OIDC spec allows for custom scopes. In Auth0 that means metadata (application level or user level) mapped to the claims (scopes) using a rule.
In the startup.cs file add additional scopes
```cs
                options.Scope.Add("openid email profile");
```
in Auth0 you add metadata in the users scopes tab
```json
{
  "lccid": "lcc-1122334"
}
```
And use rules to map this to a namespaced scope 
```js
function (user, context, callback) {
  // TODO: implement your rule
  const namespace = 'https://lcc.planbpoc.com/';
  context.idToken[namespace + 'lccid'] = user.lccid;
  callback(null, user, context);
}
```
The URI doesn't have to resolve to real end point.

Now you can add that claim to the scope
```cs
                options.Scope.Add("openid email profile lccid");
```
This will pull through the custom claim as well. This would probably be set using the management api.

### stopping the default claim mapping behaviour
With the default mappings we get
<table class="table">
            <thead>
            <tr>
                <th>
                    Claim
                </th>
                <th>
                    Value
                </th>
            </tr>
            </thead>
            <tbody>
                <tr>
                    <td>https://lcc.planbpoc.com/lccid</td>
                    <td>lcc-1122334</td>
                </tr>
                <tr>
                    <td>nickname</td>
                    <td>ian.stafford</td>
                </tr>
                <tr>
                    <td>name</td>
                    <td>ian.stafford@leeds.gov.uk</td>
                </tr>
                <tr>
                    <td>picture</td>
                    <td>https://s.gravatar.com/avatar/228e43ab15a654d84695cba697666b4d?s=480&amp;r=pg&amp;d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fia.png</td>
                </tr>
                <tr>
                    <td>updated_at</td>
                    <td>&quot;2018-05-31T11:10:19.659Z&quot;</td>
                </tr>
                <tr>
                    <td>http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress</td>
                    <td>ian.stafford@leeds.gov.uk</td>
                </tr>
                <tr>
                    <td>email_verified</td>
                    <td>true</td>
                </tr>
                <tr>
                    <td>http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier</td>
                    <td>auth0|5b0694935d7d1617fd7f136d</td>
                </tr>
            </tbody>
        </table>

To stop the default behaviour of mapping claims you can insert the following line in the startup class
```cs
            app.UseStaticFiles();

            // This method stops asp.net core identity middleware from mapping the claims to internal ones.
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            app.UseAuthentication();
```
This goes in the configure method in the startup class
Now the claims look like this
<table class="table">
            <thead>
            <tr>
                <th>
                    Claim
                </th>
                <th>
                    Value
                </th>
            </tr>
            </thead>
            <tbody>
                <tr>
                    <td>https://lcc.planbpoc.com/lccid</td>
                    <td>lcc-1122334</td>
                </tr>
                <tr>
                    <td>nickname</td>
                    <td>ian.stafford</td>
                </tr>
                <tr>
                    <td>name</td>
                    <td>ian.stafford@leeds.gov.uk</td>
                </tr>
                <tr>
                    <td>picture</td>
                    <td>https://s.gravatar.com/avatar/228e43ab15a654d84695cba697666b4d?s=480&amp;r=pg&amp;d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fia.png</td>
                </tr>
                <tr>
                    <td>updated_at</td>
                    <td>&quot;2018-05-31T11:13:15.268Z&quot;</td>
                </tr>
                <tr>
                    <td>email</td>
                    <td>ian.stafford@leeds.gov.uk</td>
                </tr>
                <tr>
                    <td>email_verified</td>
                    <td>true</td>
                </tr>
                <tr>
                    <td>sub</td>
                    <td>auth0|5b0694935d7d1617fd7f136d</td>
                </tr>
            </tbody>
        </table>

Noteabley the sub claim (subject identifier from the json web token) is now visible as sub not http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier