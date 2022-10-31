# Add Referans
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;

# Add WebConfig ConnectionStrings

  <connectionStrings>
    <add name="connectionStringsName" connectionString="I7e/GcNwgGs5tC3crJDJG3AfdbKBCxCL2cYSA8Lg5I8OHrxpf96Rht2TsGSOjDeWWXof" providerName="System.Data.SqlClient" />
  </connectionStrings>
  
  //If the connectionString is encrypted, we will protect it from the hosting staff.
  //Develop your SQL Injection models
        #region SqlInjection
        public string SqlInjection(string text)
        {
            if (!string.IsNullOrEmpty(text) && !string.IsNullOrEmpty(text))
            {
                text = text.Replace("&gt;", "");
                text = text.Replace("&lt;", "");
                text = text.Replace("--", "");
                text = text.Replace("'", "");
                text = text.Replace("char ", "");
                text = text.Replace("delete ", "");
                text = text.Replace("insert ", "");
                text = text.Replace("update ", "");
                text = text.Replace("select ", "");
                text = text.Replace("truncate ", "");
                text = text.Replace("union ", "");
                text = text.Replace("script ", "");
            }

            return text;
        }
        #endregion
  # Add Startup 
  
    public class Startup    {
        
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration configuration = new HttpConfiguration();
            Configure(app);

            WebApiConfig.Register(configuration);
            app.UseWebApi(configuration);
        }

        private void Configure(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions options = new OAuthAuthorizationServerOptions()
            {
                TokenEndpointPath = new Microsoft.Owin.PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(60),
                AllowInsecureHttp = true,
                Provider = new AuthorizationServerProvider(),
                //RefreshTokenProvider = new RefreshTokenProvider()
            };

            app.UseOAuthAuthorizationServer(options);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
    
  # Add AuthorizationServerProvider
    
    public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            string pass = SqlInjection(context.Password.TrimStart().TrimEnd());
            string encPass = Cryptography.ToMD5(pass);

            var account = repo.GetUserUserNamePass(context.UserName, context.Password);
            if (account.success == true)
            {
                if (context.UserName.Equals(account.userName, StringComparison.OrdinalIgnoreCase) && account.userPass == encPass)
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(new Claim("sub", context.UserName));
                    identity.AddClaim(new Claim("role", "Admin"));
                    context.Validated(identity);
                }
                else
                {
                    context.SetError("invalid_grant", "the username or password is incorrect.");
                }
            }
            else
            {
                context.SetError("invalid_grant", "the username or password is incorrect.");
            }
        }
    
    
    
