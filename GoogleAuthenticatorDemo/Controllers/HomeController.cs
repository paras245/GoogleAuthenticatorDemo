using Google.Authenticator;
using GoogleAuthenticatorDemo.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Security;

namespace GoogleAuthenticatorDemo.Controllers
{
    //Access-Modifier ControllerName : InheritedClass Name
    public class HomeController : Controller
    {

        //Access-Modifier Return Type MethodName
        public ActionResult Index()
        {

            //If statement to check authencation
            if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {

                //Then redirect me to login
                return RedirectToAction("Login");
            }

            //Return View Function
            return View();
        }


        //Access Modifier Return Type MethodName
        public ActionResult About()
        {

            //If Statement
            if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {
                //Then redired me to login
                return RedirectToAction("Login");
            }


            //Viewbag for message to show on About page
            ViewBag.Message = "Your application description page.";

            //return ViewResult
            return View();
        }

        public ActionResult Contact()
        {

            //If Statement
            if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {

                //then redirect me to login
                return RedirectToAction("Login");
            }

            //View Bag
            ViewBag.Message = "Your contact page.";

            //Return ViewResult
            return View();
        }

        public ActionResult Login()
        {
            Session["UserName"] = null;
            Session["IsValidTwoFactorAuthentication"] = null;
            return View();
        }


        //Take the username + secret key and bool of secretisbase32 and encode it to utf8
        private static byte[] ConvertSecretToBytes(string secret, bool secretIsBase32) =>
           secretIsBase32 ? Base32Encoding.ToBytes(secret) : Encoding.UTF8.GetBytes(secret);


        [HttpPost]
        public ActionResult Login(LoginModel login)
        {
            bool status = false;

            //If statement
            if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {

                //Take Google auth key from WebConfig
                string googleAuthKey = WebConfigurationManager.AppSettings["GoogleAuthKey"];

                //Combine UserName and WebConfig key
                string UserUniqueKey = (login.UserName + googleAuthKey);

                //Take UserName And Password As Static - Admin As User And 12345 As Password
                if (login.UserName == "Paras" && login.Password == "12345")
                {
                    Session["UserName"] = login.UserName;

                    //Two Factor Authentication Setup
                    TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();

                    //Send code on mail instead QR Code 
                    var setupInfo = TwoFacAuth.GenerateSetupCode("tbs.bhavikshah@gmail.com", login.UserName, ConvertSecretToBytes(UserUniqueKey, false), 300);

                    // var setupInfo = TwoFacAuth.GenerateSetupCode("TestAuthDemoTwoFactor.com", login.UserName, ConvertSecretToBytes(UserUniqueKey, false), 300);
                    Session["UserUniqueKey"] = UserUniqueKey;
                    // ViewBag.BarcodeImageUrl = setupInfo.QrCodeSetupImageUrl;
                    ViewBag.SetupCode = setupInfo.ManualEntryKey;
                    status = true;
                }
            }
            else
            {
                return RedirectToAction("Index");
            }


            ViewBag.Status = status;
            return View();
        }


        /// <summary>
        /// TwoFactorAuthenticate
        /// </summary>
        /// <returns></returns>
        public ActionResult TwoFactorAuthenticate()
        {

            //Get the Entered number
            var token = Request["CodeDigit"];
            TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();

            //Get the UserUniqueKey
            string UserUniqueKey = Session["UserUniqueKey"].ToString();

            //Chech validity
            bool isValid = TwoFacAuth.ValidateTwoFactorPIN(UserUniqueKey, token, false);

            //If its valid then login or else redirect
            if (isValid)
            {
                HttpCookie TwoFCookie = new HttpCookie("TwoFCookie");
                string UserCode = Convert.ToBase64String(MachineKey.Protect(Encoding.UTF8.GetBytes(UserUniqueKey)));

                Session["IsValidTwoFactorAuthentication"] = true;
                return RedirectToAction("Index");
            }

            ViewBag.Message = "Google Two Factor PIN is expired or wrong";
            return RedirectToAction("Login");
        }


        /// <summary>
        /// Logoff
        /// </summary>
        /// <returns></returns>
        public ActionResult Logoff()
        {
            Session["UserName"] = null;
            Session["IsValidTwoFactorAuthentication"] = null;
            return RedirectToAction("Login");
        }


    }
}