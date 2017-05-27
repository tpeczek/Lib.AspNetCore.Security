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
        internal const string ScriptTagName = "script";
        internal const string CspScriptTagName = "csp-script";
        internal const string StyleTagName = "style";
        internal const string CspStyleTagName = "csp-style";

        internal const string CspAttribute = "asp-csp";
        internal const string CspAttributeCacheValue = "cache";

        internal const string NonceAttribute = "nonce";
        #endregion

        #region Fields
        private readonly IContentSecurityPolicyInlineExecutionFeature _cspFeature;
        #endregion

        #region Constructor
        internal ContentSecurityPolicyHelper(ViewContext viewContext)
        {
            _cspFeature = viewContext.HttpContext.Features.Get<IContentSecurityPolicyInlineExecutionFeature>();
        }
        #endregion

        #region Methods
        internal ContentSecurityPolicyInlineExecution GetCurrentInlineExecution(string elementTagName)
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

        internal string GetCurrentNonce()
        {
            return _cspFeature?.Nonce;
        }

        internal string GetHashFromCache(string uniqueId)
        {
            return _cspFeature.GetHashFromCache(uniqueId);
        }

        internal void AddHashToCache(string uniqueId, string hash)
        {
            _cspFeature.AddHashToCache(uniqueId, hash);
        }

        internal void AddHashToInlineExecutionSources(string elementTagName, string elementHash)
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

        internal static string ComputeHash(string elementContent)
        {
            elementContent = elementContent.Replace("\r\n", "\n");
            byte[] elementHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(elementContent));

            return Convert.ToBase64String(elementHashBytes);
        } 
        #endregion
    }
}
