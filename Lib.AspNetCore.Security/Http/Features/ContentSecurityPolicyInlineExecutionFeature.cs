using System;
using System.Collections.Generic;
using Lib.AspNetCore.Security.Http.Headers;
using System.Security.Cryptography;

namespace Lib.AspNetCore.Security.Http.Features
{
    internal class ContentSecurityPolicyInlineExecutionFeature : IContentSecurityPolicyInlineExecutionFeature
    {
        #region Fields
        private const int _nonceLength = 128 / 8;
        #endregion

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
                Nonce = GenerateNonce();
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

        #region Methods
        private static string GenerateNonce()
        {
            string nonce = null;

            using (RandomNumberGenerator nonceGenerator = RandomNumberGenerator.Create())
            {
                byte[] nonceBytes = new byte[_nonceLength];
                nonceGenerator.GetBytes(nonceBytes);
                nonce = Convert.ToBase64String(nonceBytes);
            }

            return nonce;
        }
        #endregion
    }
}
