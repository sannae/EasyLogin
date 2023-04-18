using EasyLogin.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Web.Http;
using static System.Net.Mime.MediaTypeNames;

namespace EasyLogin.Controllers
{
    public class LoginController : ApiController
    {
        // POST api/login
        public JObject Post(LoginModel login)
        {
            var output = new JObject();
            output["result"] = "OK";

            List<LoginModel> allUsers = AuthorizedUsers();
            LoginModel selectedUser = allUsers.Where(u => u.Email.Equals(login.Email)).FirstOrDefault();

            // Check if email is in list
            if (selectedUser == null)
            {
                output["result"] = "KO";
                return output;
            }

            // Encode password using Base64
            string encodedPassword = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(login.Password));

            // Check password
            if (!encodedPassword.Equals(selectedUser.Password))
            {
                output["result"] = "KO";
                return output;
            }

            return output;
        }

        private List<LoginModel> AuthorizedUsers()
        {
            // Users list file location
            string usersJsonFilePath = @"App_Data\users.json";

            string usersFullPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, usersJsonFilePath);

            return JsonConvert.DeserializeObject<List<LoginModel>>(File.ReadAllText(usersFullPath));
        }
    }
}
