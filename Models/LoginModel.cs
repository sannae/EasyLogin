using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace EasyLogin.Models
{
    public class LoginModel
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}