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
    }
}
