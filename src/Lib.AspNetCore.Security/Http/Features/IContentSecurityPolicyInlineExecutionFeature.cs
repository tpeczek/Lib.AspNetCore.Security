using System.Collections.Generic;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Security.Http.Features
{
    /// <summary>
    /// Provides support for inline execution aspects of Content Security Policy.
    /// </summary>
    public interface IContentSecurityPolicyInlineExecutionFeature
    {
        #region Properties
        /// <summary>
        /// Gets the inline execution mode for scripts.
        /// </summary>
        ContentSecurityPolicyInlineExecution ScriptInlineExecution { get; }

        /// <summary>
        /// Gets the inline execution mode for stylesheets.
        /// </summary>
        ContentSecurityPolicyInlineExecution StyleInlineExecution { get; }

        /// <summary>
        /// Gets the nonce for <see cref="ContentSecurityPolicyInlineExecution.Nonce"/>.
        /// </summary>
        string Nonce { get; }

        /// <summary>
        /// Gets the scripts hashes collection for <see cref="ContentSecurityPolicyInlineExecution.Hash"/>.
        /// </summary>
        ICollection<string> ScriptsHashes { get; }

        /// <summary>
        /// Gets the styles hashes collection for <see cref="ContentSecurityPolicyInlineExecution.Hash"/>.
        /// </summary>
        ICollection<string> StylesHashes { get; }
        #endregion

        #region Methods
        /// <summary>
        /// Computes the hash for given content.
        /// </summary>
        /// <param name="hashAlgorithm">The algorithm for computing the hash.</param>
        /// <param name="elementContent">The content for which the hash is to be computed.</param>
        /// <returns>The hash.</returns>
        string ComputeHash(ContentSecurityPolicyInlineExecution hashAlgorithm, string elementContent);

        /// <summary>
        /// Gets the hash from cache.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <returns>The hash.</returns>
        string GetHashFromCache(string cacheKey);

        /// <summary>
        /// Adds the hash to cache.
        /// </summary>
        /// <param name="cacheKey">The cache key.</param>
        /// <param name="hash">The hash.</param>
        void AddHashToCache(string cacheKey, string hash);
        #endregion
    }
}
