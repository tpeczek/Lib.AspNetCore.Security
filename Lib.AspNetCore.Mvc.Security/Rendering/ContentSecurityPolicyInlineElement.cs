using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.Rendering;
using Lib.AspNetCore.Mvc.Security.Filters;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Text.Encodings.Web;

namespace Lib.AspNetCore.Mvc.Security.Rendering
{
    internal class ContentSecurityPolicyInlineElement : IDisposable
    {
        #region Fields
        private readonly ViewContext _viewContext;
        private readonly TextWriter _viewContextWriter;
        private readonly ContentSecurityPolicyInlineExecution _currentInlineExecutionPolicy;
        private readonly TagBuilder _elementTag;
        #endregion

        #region Constructor
        internal ContentSecurityPolicyInlineElement(ViewContext context, string elementTagName, IDictionary<string, object> htmlAttributes)
        {
            _viewContext = context;

            _currentInlineExecutionPolicy = ContentSecurityPolicyHelper.GetCurrentInlineExecutionPolicy(_viewContext, elementTagName);

            _elementTag = new TagBuilder(elementTagName);
            _elementTag.MergeAttributes(htmlAttributes);
            if (_currentInlineExecutionPolicy == ContentSecurityPolicyInlineExecution.Nonce)
            {
                _elementTag.MergeAttribute(ContentSecurityPolicyHelper.NonceAttribute, ContentSecurityPolicyHelper.GetCurrentNonce(_viewContext));
            }

            _elementTag.TagRenderMode = TagRenderMode.StartTag;
            _elementTag.WriteTo(_viewContext.Writer, HtmlEncoder.Default);

            if (_currentInlineExecutionPolicy == ContentSecurityPolicyInlineExecution.Hash)
            {
                _viewContextWriter = _viewContext.Writer;
                _viewContext.Writer = new StringWriter();
            }
        }
        #endregion

        #region IDisposable Members
        public void Dispose()
        {
            if (_currentInlineExecutionPolicy == ContentSecurityPolicyInlineExecution.Hash)
            {
                StringBuilder elementInnerHtmlBuilder = ((StringWriter)_viewContext.Writer).GetStringBuilder();
                string elementInnerHtml = elementInnerHtmlBuilder.ToString();

                string elementHash = ContentSecurityPolicyHelper.ComputeHash(elementInnerHtml);
                ContentSecurityPolicyHelper.AddHashToInlineExecutionPolicyList(_viewContext, _elementTag.TagName, elementHash);

                _viewContext.Writer.Dispose();
                _viewContext.Writer = _viewContextWriter;
                _viewContext.Writer.Write(elementInnerHtml);
            }

            _elementTag.TagRenderMode = TagRenderMode.EndTag;
            _elementTag.WriteTo(_viewContext.Writer, HtmlEncoder.Default);
        }
        #endregion
    }
}
