﻿using EasyLogin.Models;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Claims;
using System.Web.Caching;
using System.Web.Http;
using System.Web.UI.WebControls;
using static System.Net.Mime.MediaTypeNames;

namespace EasyLogin.Controllers
{
    public class LoginController : ApiController
    {
        private const string usersJsonFilePath = @"App_Data\users.json";

        // POST api/login
        public JObject Post(LoginModel login)
        {
            var output = new JObject();

            output["result"] = CheckUserLogin(login.Email, login.Password) ?
                GenerateJwtToken(login.Email) : 
                "KO";

            return output;
        }

        /// <summary>
        /// Validates the user login based on email and password
        /// </summary>
        /// <param name="email"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private bool CheckUserLogin(string email, string password)
        {
            // Read users from file
            List<LoginModel> allUsers = AuthorizedUsers();

            // Check if user is in list
            LoginModel selectedUser = allUsers.Where(u => u.Email.Equals(email)).FirstOrDefault();
            if (selectedUser == null)
                return false;

            // Check if user has a valid password
            if (selectedUser.Password.IsNullOrEmpty())
                return false;

            // Check password
            string encodedPassword = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(password));
            if (!encodedPassword.Equals(selectedUser.Password))
                return false;

            return true;
        }

        /// <summary>
        /// Retrieves the list of authorized users from the JSON users file
        /// </summary>
        /// <returns></returns>
        private List<LoginModel> AuthorizedUsers()
        {
            // Users list file location
            string usersFullPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, usersJsonFilePath);

            return JsonConvert.DeserializeObject<List<LoginModel>>(File.ReadAllText(usersFullPath));
        }

        /// <summary>
        /// Returns a JWT token based on user email
        /// For the sake of simplicity, expiration and secret key are not handled here.
        /// Source: https://stackoverflow.com/a/40284152/11935591
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        private string GenerateJwtToken(string email)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // Attributes related to the token
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Email, email)
                })
            };
            SecurityToken securityToken = tokenHandler.CreateToken(tokenDescriptor);
            string token = tokenHandler.WriteToken(securityToken);

            // Just checking email in token
            // TODO: not really sure if it's the best way
            var emailInJwtToken = (new JwtSecurityTokenHandler()).ReadJwtToken(token).Claims
                .Where(t => t.Type == "email").FirstOrDefault()
                .Value;
            if (!emailInJwtToken.Equals(email))
                throw new Exception("Could not generate token out of provided email");

            return token;
        }
    }
}
