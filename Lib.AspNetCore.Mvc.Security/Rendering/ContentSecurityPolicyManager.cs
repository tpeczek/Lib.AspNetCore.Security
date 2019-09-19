using Lib.AspNetCore.Security.Http.Headers;
using Microsoft.AspNetCore.Http;

namespace Lib.AspNetCore.Mvc.Security.Rendering
{
    /// <summary>
    /// Supports adding content hashes to the ContentSecurityPolicy
    /// </summary>
    public interface IContentSecurityPolicyManager
    {
        /// <summary>
        /// Get the current nonce value or hash for script content 
        /// </summary>
        /// <param name="httpContext">The Http Context</param>
        /// <param name="content">The content to be hashed</param>
        /// <returns>current nonce value or hash of content</returns>
        string AddScriptContentSecurityPolicy(HttpContext httpContext, string content);

        /// <summary>
        /// Get the current nonce value or hash for style content 
        /// </summary>
        /// <param name="httpContext">The Http Context</param>
        /// <param name="content">The content to be hashed</param>
        /// <returns>current nonce value or hash of content</returns>
        string AddStyleContentSecurityPolicy(HttpContext httpContext, string content);
    }

    /// <summary>
    /// Supports adding content hashes to the ContentSecurityPolicy
    /// </summary>
    public class ContentSecurityPolicyManager : IContentSecurityPolicyManager
    {
        /// <summary>
        /// Get the current nonce value or hash for script content 
        /// </summary>
        /// <param name="httpContext">The Http Context</param>
        /// <param name="content">The content to be hashed</param>
        /// <returns>current nonce value or hash of content</returns>
        public string AddScriptContentSecurityPolicy(HttpContext httpContext, string content)
        {
            return ApplyContentSecurityPolicy(httpContext, ContentSecurityPolicyHelper.ScriptTagName, content);
        }

        /// <summary>
        /// Get the current nonce value or hash for style content 
        /// </summary>
        /// <param name="httpContext">The Http Context</param>
        /// <param name="content">The content to be hashed</param>
        /// <returns>current nonce value or hash of content</returns>
        public string AddStyleContentSecurityPolicy(HttpContext httpContext, string content)
        {
            return ApplyContentSecurityPolicy(httpContext, ContentSecurityPolicyHelper.StyleTagName, content);
        }

        private string ApplyContentSecurityPolicy(HttpContext httpContext, string tagName, string content)
        {
            ContentSecurityPolicyHelper cspHelper = new ContentSecurityPolicyHelper(httpContext);

            ContentSecurityPolicyInlineExecution currentInlineExecution = cspHelper.GetCurrentInlineExecution(tagName);

            if (currentInlineExecution == ContentSecurityPolicyInlineExecution.Nonce)
            {
                return cspHelper.GetCurrentNonce();
            }
            else if (currentInlineExecution.IsHashBased())
            {
                var contentHash = ContentSecurityPolicyHelper.ComputeHash(currentInlineExecution, content);

                cspHelper.AddHashToInlineExecutionSources(tagName, contentHash);

                return contentHash;
            }

            return string.Empty;
        }
    }
}