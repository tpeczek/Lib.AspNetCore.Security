using System;
using System.Text;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security.Http.Features
{
    internal class ContentSecurityPolicyInlineExecutionFeature : IContentSecurityPolicyInlineExecutionFeature
    {
        #region Structs
        private struct HashAlgorithmInfo
        {
            public string SourcePrefix { get; }

            public Func<HashAlgorithm> AlgorithmImplementationCreator { get; }

            public HashAlgorithmInfo(string sourcePrefix, Func<HashAlgorithm> algorithmImplementationCreator)
            {
                SourcePrefix = sourcePrefix;
                AlgorithmImplementationCreator = algorithmImplementationCreator;
            }
        }
        #endregion

        #region Fields
        private const int _nonceLength = 128 / 8;

        private readonly static IReadOnlyDictionary<ContentSecurityPolicyInlineExecution, HashAlgorithmInfo> _hashAlgorithmsInfos = new Dictionary<ContentSecurityPolicyInlineExecution, HashAlgorithmInfo>
        {
            { ContentSecurityPolicyInlineExecution.Hash, new HashAlgorithmInfo("sha256-", SHA256.Create) },
            { ContentSecurityPolicyInlineExecution.Hash384, new HashAlgorithmInfo("sha384-", SHA384.Create) },
            { ContentSecurityPolicyInlineExecution.Hash512, new HashAlgorithmInfo("sha512-", SHA512.Create) }
        };

        private readonly ConcurrentDictionary<string, string> _hashesCache;
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

            if (ScriptInlineExecution.IsHashBased())
            {
                ScriptsHashes = new List<string>();
            }

            if (StyleInlineExecution.IsHashBased())
            {
                StylesHashes = new List<string>();
            }
        }
        #endregion

        #region Methods
        public string ComputeHash(ContentSecurityPolicyInlineExecution hashAlgorithm, string elementContent)
        {
            HashAlgorithmInfo hashAlgorithmInfo = _hashAlgorithmsInfos[hashAlgorithm];
            byte[] elementHashBytes = null;

            using (HashAlgorithm hashAlgorithmImplementation = hashAlgorithmInfo.AlgorithmImplementationCreator())
            {
                elementContent = elementContent.Replace("\r\n", "\n");
                elementHashBytes = hashAlgorithmImplementation.ComputeHash(Encoding.UTF8.GetBytes(elementContent));
            }

            return hashAlgorithmInfo.SourcePrefix + Convert.ToBase64String(elementHashBytes);
        }

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
