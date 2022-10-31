using ApiModel;
using Dapper;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApiToken.Repos
{
    public class WebRepo
    {
        #region ctor
        string connectionString = string.Empty;

        public WebRepo()
        {
            string cstr = ConfigurationManager.ConnectionStrings["WebConfigConnectionString"].ConnectionString;

            var decrypted = SaCrypto.Decrypt(cstr, "");

            connectionString = decrypted;
        }
        #endregion

        #region Get User
        public UserModel GetUserUserNamePass(string userName = null, string userPass = null)
        {
            UserModel model = new UserModel();
            try
            {
                string pass = SqlInjection(userPass.TrimStart().TrimEnd());
                string encPass = Cryptography.ToMD5(pass);

                using (IDbConnection db = new SqlConnection(connectionString))
                {
                    DynamicParameters p = new DynamicParameters();
                    p.Add("@userName", userName);
                    p.Add("@userPass", encPass);

                    model = db.QueryFirstOrDefault<UserModel>("mssql stored procedure", p, commandType: CommandType.StoredProcedure);

                    if (model != null && model.ID > 0)
                    {
                        model.success = true;
                        return model;
                    }
                    else
                    {
                        return new UserModel() { success = false, message = "Hatalı" };
                    }

                }
            }
            catch (Exception)
            {
                return new UserModel() { success = false, message = "Hatalı" };
            }
        }
        #endregion
    }
}