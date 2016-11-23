using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc.Rendering;
using Lib.AspNetCore.Mvc.Security.Filters;

namespace Lib.AspNetCore.Mvc.Security.Rendering
{
    internal class ContentSecurityPolicyHelper
    {
        #region Constants
        internal const string ScriptTagName = "script";
        internal const string CspScriptTagName = "csp-script";
        internal const string StyleTagName = "style";
        internal const string CspStyleTagName = "csp-style";

        internal const string CspAttribute = "csp";
        internal const string NonceAttribute = "nonce";

        private const string _sha256SourceFormat = " 'sha256-{0}'";
        #endregion

        #region Fields
        private static IDictionary<string, string> _inlineExecutionContextKeys = new Dictionary<string, string>
        {
            { ScriptTagName, ContentSecurityPolicyAttribute.InlineExecutionContextKeys[ContentSecurityPolicyAttribute.ScriptDirective] },
            { StyleTagName, ContentSecurityPolicyAttribute.InlineExecutionContextKeys[ContentSecurityPolicyAttribute.StyleDirective] }
        };

        private static IDictionary<string, string> _hashListBuilderContextKeys = new Dictionary<string, string>
        {
            { ScriptTagName, ContentSecurityPolicyAttribute.HashListBuilderContextKeys[ContentSecurityPolicyAttribute.ScriptDirective] },
            { StyleTagName, ContentSecurityPolicyAttribute.HashListBuilderContextKeys[ContentSecurityPolicyAttribute.StyleDirective] }
        };
        #endregion

        #region Methods
        internal static ContentSecurityPolicyInlineExecution GetCurrentInlineExecutionPolicy(ViewContext viewContext, string elementTagName)
        {
            return (ContentSecurityPolicyInlineExecution)viewContext.HttpContext.Items[_inlineExecutionContextKeys[elementTagName]];
        }

        internal static string GetCurrentNonce(ViewContext viewContext)
        {
            return (string)viewContext.HttpContext.Items[ContentSecurityPolicyAttribute.NonceRandomContextKey];
        }

        internal static string ComputeHash(string elementContent)
        {
            elementContent = elementContent.Replace("\r\n", "\n");
            byte[] elementHashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(elementContent));

            return Convert.ToBase64String(elementHashBytes);
        }

        internal static void AddHashToInlineExecutionPolicyList(ViewContext viewContext, string elementTagName, string elementHash)
        {
            ((StringBuilder)viewContext.HttpContext.Items[_hashListBuilderContextKeys[elementTagName]]).AppendFormat(_sha256SourceFormat, elementHash);
        }
        #endregion
    }
}
