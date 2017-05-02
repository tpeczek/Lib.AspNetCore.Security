using System;
using System.Collections.Generic;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security.Http.Features
{
    internal class ContentSecurityPolicyInlineExecutionFeature : IContentSecurityPolicyInlineExecutionFeature
    {
        #region Properties
        public ContentSecurityPolicyInlineExecution ScriptInlineExecution { get; }

        public ContentSecurityPolicyInlineExecution StyleInlineExecution { get; }

        public string Nonce { get; }

        public ICollection<string> ScriptsHashes { get; }

        public ICollection<string> StylesHashes { get; }
        #endregion

        #region Constructor
        public ContentSecurityPolicyInlineExecutionFeature(ContentSecurityPolicyHeaderValue csp)
        {
            if (csp == null)
            {
                throw new ArgumentNullException(nameof(csp));
            }

            ScriptInlineExecution = csp.ScriptInlineExecution;
            StyleInlineExecution = csp.StyleInlineExecution;

            if ((ScriptInlineExecution == ContentSecurityPolicyInlineExecution.Nonce) || (StyleInlineExecution == ContentSecurityPolicyInlineExecution.Nonce))
            {
                Nonce = Guid.NewGuid().ToString("N");
            }

            if (ScriptInlineExecution == ContentSecurityPolicyInlineExecution.Hash)
            {
                ScriptsHashes = new List<string>();
            }

            if (StyleInlineExecution == ContentSecurityPolicyInlineExecution.Hash)
            {
                StylesHashes = new List<string>();
            }
        }
        #endregion
    }
}
