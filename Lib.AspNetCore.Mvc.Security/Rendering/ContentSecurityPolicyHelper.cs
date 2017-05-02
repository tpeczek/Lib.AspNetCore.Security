using System;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc.Rendering;
using Lib.AspNetCore.Security.Http.Features;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Mvc.Security.Rendering
{
    internal class ContentSecurityPolicyHelper
    {
        #region Constants
        public const string ScriptTagName = "script";
        public const string CspScriptTagName = "csp-script";
        public const string StyleTagName = "style";
        public const string CspStyleTagName = "csp-style";

        public const string CspAttribute = "asp-csp";
        public const string NonceAttribute = "nonce";
        #endregion

        #region Fields
        private readonly IContentSecurityPolicyInlineExecutionFeature _cspFeature;
        #endregion

        #region Constructor
        public ContentSecurityPolicyHelper(ViewContext viewContext)
        {
            _cspFeature = viewContext.HttpContext.Features.Get<IContentSecurityPolicyInlineExecutionFeature>();
        }
        #endregion

        #region Methods
        public ContentSecurityPolicyInlineExecution GetCurrentInlineExecution(string elementTagName)
        {
            ContentSecurityPolicyInlineExecution inlineExecution = ContentSecurityPolicyInlineExecution.Unsafe;

            if (_cspFeature != null)
            {
                switch (elementTagName)
                {
                    case ScriptTagName:
                        inlineExecution = _cspFeature.ScriptInlineExecution;
                        break;
                    case StyleTagName:
                        inlineExecution = _cspFeature.StyleInlineExecution;
                        break;
                }
            }

            return inlineExecution;
        }

        public string GetCurrentNonce()
        {
            return _cspFeature?.Nonce;
        }

        public void AddHashToInlineExecutionSources(string elementTagName, string elementHash)
        {
            switch (elementTagName)
            {
                case ScriptTagName:
                    _cspFeature.ScriptsHashes.Add(elementHash);
                    break;
                case StyleTagName:
                    _cspFeature.StylesHashes.Add(elementHash);
                    break;
            }
        }

        public static string ComputeHash(string elementContent)
        {
            elementContent = elementContent.Replace("\r\n", "\n");
            byte[] elementHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(elementContent));

            return Convert.ToBase64String(elementHashBytes);
        }
        #endregion
    }
}
