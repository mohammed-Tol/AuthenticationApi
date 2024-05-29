using AuthenticationApi.DataAccess;
using AuthenticationClassLibrary;
using AuthenticationClassLibrary.Models;
using Microsoft.Data.SqlClient;
using System.Data;

namespace AuthenticationApi.Infrastructure
{
    public interface IUserServiceAsync
    {
        Task<User?> AuthenticateAsync(AuthenticationRequest model);
        Task<User> GetUserDetails(int userId);

        Task<bool> UpdatePassword(string username, string newPassword);

        Task<int?> GetEmployeeIdByEmailAsync(string email);
    }

    public class UserService : BaseDataAccess, IUserServiceAsync
    {
        public UserService(IConfiguration config) : base(config)
        {

        }

        public async Task<User?> AuthenticateAsync(AuthenticationRequest model)
        {
            User? user = null;
            var parameters = new[]
            {
        new SqlParameter("@inputUsername", model.Username),
        new SqlParameter("@inputPassword", model.Password)
    };

            using (var reader = ExecuteReader("sp_GetUserByUsernameAndPassword", CommandType.StoredProcedure, parameters))
            {
                if (reader.HasRows)
                {
                    await reader.ReadAsync();
                    var userId = reader.IsDBNull(0) ? (int?)null : reader.GetInt32(0);
                    var username = reader.IsDBNull(1) ? null : reader.GetString(1);
                    var password = reader.IsDBNull(2) ? null : reader.GetString(2);
                    var lastPasswordChange = reader.IsDBNull(3) ? (DateTime?)null : reader.GetDateTime(3);
                    var isActive = reader.IsDBNull(4) ? (bool?)null : reader.GetBoolean(4);
                    var roleId = reader.IsDBNull(5) ? (int?)null : reader.GetInt32(5);

                    if (userId.HasValue && username != null && password != null && isActive.HasValue && roleId.HasValue)
                    {
                        bool mustChangePassword = !lastPasswordChange.HasValue;

                        user = new User
                        {
                            UserId = userId.Value,
                            UserName = username,
                            Password = password,
                            Last_Password_Change = lastPasswordChange,
                            isActive = isActive.Value,
                            RoleID = roleId.Value,
                            MustChangePassword = mustChangePassword
                        };
                    }
                }
            }
            return user;
        }

        public async Task<int?> GetEmployeeIdByEmailAsync(string email)
        {
            int? employeeId = null;
            var parameters = new[]
            {
        new SqlParameter("@Email", email)
    };

            using (var reader = ExecuteReader("sp_GetEmployeeIdByEmail", CommandType.StoredProcedure, parameters))
            {
                if (reader.HasRows)
                {
                    await reader.ReadAsync();
                    employeeId = reader.IsDBNull(0) ? (int?)null : reader.GetInt32(0);
                }
            }

            return employeeId;
        }
        public async Task<User> GetUserDetails(int userId)
        {
            User user = null;

            var parameters = new[]
            {
                new SqlParameter("@inputUserId", userId)
            };

            using (var reader = ExecuteReader("sp_GetUserDetailsById", CommandType.StoredProcedure, parameters))
            {
                if (reader.HasRows)
                {
                    await reader.ReadAsync(); // Read the first row asynchronously
                    var username = reader.GetString(1);
                    var password = reader.GetString(2);
                    var lastPasswordChange = reader.IsDBNull(3) ? null : (DateTime?)reader.GetDateTime(3);
                    var isActive = reader.GetBoolean(4);

                    var roleId = reader.GetInt32(5);

                    // Create the User object
                    user = new User
                    {
                        UserId = userId,
                        UserName = username,
                        Password = password,
                        Last_Password_Change = lastPasswordChange,
                        isActive = isActive,

                        RoleID = roleId
                    };
                }
            }
            return user;
        }

        public async Task<bool> UpdatePassword(string username, string newPassword)
        {
            try
            {
                var parameters = new[]
                {
            new SqlParameter("@Username", username),
            new SqlParameter("@NewPassword", newPassword)
        };

                await Task.Run(() => ExecuteNonQuery("sp_UpdateUserPassword", CommandType.StoredProcedure, parameters));
                return true;
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Error updating password: {ex.Message}");
                return false;
            }
        }


    }
}