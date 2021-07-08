using IdentityModel.OidcClient;
using System;
using Serilog;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace ConsoleClientWithBrowser
{
    public class Program
    {
        static OidcClient _oidcClient;
        public const string Authority = "https://auth.dbt.agilicus.cloud";

        public static async Task Main()
        {
            Console.WriteLine("Browser will open, login, return here\n");
            await SignIn();
        }

        private static async Task SignIn()
        {
            // Begin boilerplate, just used to get an ID_TOKEN and ACCESS_TOKEN,
            // mocking up your application
            var browser = new SystemBrowser(4200);
            string redirectUri = string.Format($"http://localhost:4200/");

            var options = new OidcClientOptions
            {
                ClientId = "my-api-access",
                Authority = Authority,

                RedirectUri = redirectUri,
                Scope = "openid email profile",
                FilterClaims = false,
                Browser = browser
            };

            var serilog = new LoggerConfiguration()
                .MinimumLevel.Error()
                .Enrich.FromLogContext()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}")
                .CreateLogger();

            options.LoggerFactory.AddSerilog(serilog);
            _oidcClient = new OidcClient(options);
            var result = await _oidcClient.LoginAsync(new LoginRequest());

            ShowResult(result);
            if (!result.IsError) {
                CheckResult(result.IdentityToken, result.AccessToken);
            }
            // END BOILERPLATE
        }

        private static void ShowResult(LoginResult result)
        {
            if (result.IsError)
            {
                Console.WriteLine("\n\nError:\n{0}", result.Error);
                return;
            }

            Console.WriteLine("\n\nClaims:");
            foreach (var claim in result.User.Claims)
            {
                Console.WriteLine("{0}: {1}", claim.Type, claim.Value);
            }

            Console.WriteLine($"\nidentity token: {result.IdentityToken}");
            Console.WriteLine($"access token:   {result.AccessToken}");
            Console.WriteLine($"refresh token:  {result?.RefreshToken ?? "none"}");
        }
        private static bool CheckResult(string id_token, string access_token)
        {
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{Authority}/.well-known/openid-configuration",
                                                                                     new OpenIdConnectConfigurationRetriever());
            var openidconfig = configManager.GetConfigurationAsync().Result;
            SecurityToken token = new JwtSecurityToken();
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = Authority,
                IssuerSigningKeys = openidconfig.SigningKeys,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                ValidateAudience = false
            };
            bool good = false;
            try {
                var res = tokenHandler.ValidateToken(id_token, validationParameters, out token);
                if (res != null)
                {
                    good = true;
                }
            }
            catch (ArgumentException e)
            {
                Console.WriteLine(e.ToString());
            }
            catch (SecurityTokenDecryptionFailedException e)
            {
                Console.WriteLine(e.ToString());
            }
            catch (SecurityTokenException e)
            {
                Console.WriteLine(e.ToString());
            }
            return good;
        }
    }
}
