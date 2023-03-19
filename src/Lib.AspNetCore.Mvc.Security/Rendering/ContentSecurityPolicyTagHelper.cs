﻿using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Mvc.Security.Rendering
{
    /// <summary>
    /// TagHelper which provides support for Content Security Policy protected elements.
    /// </summary>
    [HtmlTargetElement(ContentSecurityPolicyHelper.CspStyleTagName)]
    [HtmlTargetElement(ContentSecurityPolicyHelper.StyleTagName, Attributes = ContentSecurityPolicyHelper.CspAttribute)]
    [HtmlTargetElement(ContentSecurityPolicyHelper.CspScriptTagName)]
    [HtmlTargetElement(ContentSecurityPolicyHelper.ScriptTagName, Attributes = ContentSecurityPolicyHelper.CspAttribute)]
    public class ContentSecurityPolicyTagHelper : TagHelper
    {
        #region Properties
        /// <summary>
        /// Gets or sets the view context.
        /// </summary>
        [ViewContext]
        public ViewContext ViewContext { get; set; }
        #endregion

        #region Methods
        /// <summary>
        /// Asynchronously processes the TagHelper.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="output">The output.</param>
        /// <returns></returns>
        public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
        {
            SetTagName(output);

            string uniqueId = (output.Attributes[ContentSecurityPolicyHelper.CspAttribute]?.Value?.ToString().ToLowerInvariant() == ContentSecurityPolicyHelper.CspAttributeCacheValue) ? context.UniqueId : null;
            output.Attributes.RemoveAll(ContentSecurityPolicyHelper.CspAttribute);

            await ApplyContentSecurityPolicy(output, uniqueId);
        }

        private void SetTagName(TagHelperOutput output)
        {
            if (output.TagName == ContentSecurityPolicyHelper.CspStyleTagName)
            {
                output.TagName = ContentSecurityPolicyHelper.StyleTagName;
            }
            else if (output.TagName == ContentSecurityPolicyHelper.CspScriptTagName)
            {
                output.TagName = ContentSecurityPolicyHelper.ScriptTagName;
            }
        }

        private async Task ApplyContentSecurityPolicy(TagHelperOutput output, string uniqueId)
        {
            ContentSecurityPolicyHelper cspHelper = new ContentSecurityPolicyHelper(ViewContext);

            ContentSecurityPolicyInlineExecution currentInlineExecution = cspHelper.GetCurrentInlineExecution(output.TagName);

            if (currentInlineExecution == ContentSecurityPolicyInlineExecution.Nonce)
            {
                output.Attributes.Add(ContentSecurityPolicyHelper.NonceAttribute, cspHelper.GetCurrentNonce());
            }
            else if (currentInlineExecution.IsHashBased())
            {
                string contentHash = null;

                if (!String.IsNullOrEmpty(uniqueId))
                {
                    contentHash = cspHelper.GetHashFromCache(uniqueId);
                }

                if (contentHash == null)
                {
                    string content = output.Content.IsModified ? output.Content.GetContent() : (await output.GetChildContentAsync()).GetContent();
                    contentHash = cspHelper.ComputeHash(currentInlineExecution, content);

                    if (!String.IsNullOrEmpty(uniqueId))
                    {
                        cspHelper.AddHashToCache(uniqueId, contentHash);
                    }
                }

                cspHelper.AddHashToInlineExecutionSources(output.TagName, contentHash);
            }
        }
        #endregion
    }
}
