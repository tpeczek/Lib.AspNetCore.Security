using System;
using System.Collections.Generic;
using System.Text;

namespace Lib.AspNetCore.Security.Http.Features
{
    /// <summary>
    /// Extensions for <see cref="IContentSecurityPolicyInlineExecutionFeature"/>.
    /// </summary>
    public static class ContentSecurityPolicyInlineExecutionFeatureExtensions
    {
        /// <summary>
        /// Computes the hash for given content by using current algorithm for scripts.
        /// </summary>
        /// <param name="cspFeature">The instance of <see cref="IContentSecurityPolicyInlineExecutionFeature"/>.</param>
        /// <param name="elementContent">The content for which the hash is to be computed.</param>
        /// <returns>The hash.</returns>
        public static string ComputeScriptHash(this IContentSecurityPolicyInlineExecutionFeature cspFeature, string elementContent)
        {
            return cspFeature.ComputeHash(cspFeature.ScriptInlineExecution, elementContent);
        }

        /// <summary>
        /// Computes the hash for given content by using current algorithm for styles.
        /// </summary>
        /// <param name="cspFeature">The instance of <see cref="IContentSecurityPolicyInlineExecutionFeature"/>.</param>
        /// <param name="elementContent">The content for which the hash is to be computed.</param>
        /// <returns>The hash.</returns>
        public static string ComputeStyleHash(this IContentSecurityPolicyInlineExecutionFeature cspFeature, string elementContent)
        {
            return cspFeature.ComputeHash(cspFeature.StyleInlineExecution, elementContent);
        }

        /// <summary>
        /// Computes the hash for given content by using current algorithm for scripts and adds it to scripts hashes collection.
        /// </summary>
        /// <param name="cspFeature">The instance of <see cref="IContentSecurityPolicyInlineExecutionFeature"/>.</param>
        /// <param name="elementContent">The content for which the hash is to be computed.</param>
        /// <returns>The hash.</returns>
        public static void ComputeAndAddScriptHash(this IContentSecurityPolicyInlineExecutionFeature cspFeature, string elementContent)
        {
            cspFeature.ScriptsHashes.Add(cspFeature.ComputeScriptHash(elementContent));
        }

        /// <summary>
        /// Computes the hash for given content by using current algorithm for styles and adds it to styles hashes collection.
        /// </summary>
        /// <param name="cspFeature">The instance of <see cref="IContentSecurityPolicyInlineExecutionFeature"/>.</param>
        /// <param name="elementContent">The content for which the hash is to be computed.</param>
        /// <returns>The hash.</returns>
        public static void ComputeAndAddStyleHash(this IContentSecurityPolicyInlineExecutionFeature cspFeature, string elementContent)
        {
            cspFeature.StylesHashes.Add(cspFeature.ComputeStyleHash(elementContent));
        }
    }
}
