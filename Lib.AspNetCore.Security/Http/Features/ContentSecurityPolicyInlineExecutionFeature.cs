using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security.Http.Features
{
    internal class ContentSecurityPolicyInlineExecutionFeature : IContentSecurityPolicyInlineExecutionFeature
    {
        #region Fields
        private readonly ConcurrentDictionary<string, string> _hashesCache;

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
        public ContentSecurityPolicyInlineExecutionFeature(ContentSecurityPolicyHeaderValue csp, ConcurrentDictionary<string, string> hashesCache)
        {
            if (csp == null)
            {
                throw new ArgumentNullException(nameof(csp));
            }
            _hashesCache = hashesCache ?? throw new ArgumentNullException(nameof(hashesCache));

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
        public string GetHashFromCache(string cacheKey)
        {
            string hash = null;

            _hashesCache.TryGetValue(cacheKey, out hash);

            return hash;
        }

        public void AddHashToCache(string cacheKey, string hash)
        {
            _hashesCache.TryAdd(cacheKey, hash);
        }

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
