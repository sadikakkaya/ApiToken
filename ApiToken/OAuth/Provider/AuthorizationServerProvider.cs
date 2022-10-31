
using ApiToken.Repos;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace ApiToken.OAuth.Provider
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        WebRepo repo = new WebRepo();
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }
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


    }
}