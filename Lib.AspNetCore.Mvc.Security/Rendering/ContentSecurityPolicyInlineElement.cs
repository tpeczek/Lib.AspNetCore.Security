using System;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.Rendering;
using Lib.AspNetCore.Security.Http.Headers;

namespace Lib.AspNetCore.Mvc.Security.Rendering
{
    internal class ContentSecurityPolicyInlineElement : IDisposable
    {
        #region Fields
        private readonly TagBuilder _elementTag;

        private readonly ViewContext _viewContext;
        private readonly TextWriter _viewContextWriter;

        private readonly ContentSecurityPolicyHelper _cspHelper;
        private readonly ContentSecurityPolicyInlineExecution _currentInlineExecution;
        #endregion

        #region Constructor
        public ContentSecurityPolicyInlineElement(ViewContext context, string elementTagName, IDictionary<string, object> htmlAttributes)
        {
            _viewContext = context;

            _cspHelper = new ContentSecurityPolicyHelper(_viewContext);
            _currentInlineExecution = _cspHelper.GetCurrentInlineExecution(elementTagName);

            _elementTag = new TagBuilder(elementTagName);
            _elementTag.MergeAttributes(htmlAttributes);
            if (_currentInlineExecution == ContentSecurityPolicyInlineExecution.Nonce)
            {
                _elementTag.MergeAttribute(ContentSecurityPolicyHelper.NonceAttribute, _cspHelper.GetCurrentNonce());
            }

            _elementTag.TagRenderMode = TagRenderMode.StartTag;
            _elementTag.WriteTo(_viewContext.Writer, HtmlEncoder.Default);

            if (_currentInlineExecution == ContentSecurityPolicyInlineExecution.Hash)
            {
                _viewContextWriter = _viewContext.Writer;
                _viewContext.Writer = new StringWriter();
            }
        }
        #endregion

        #region IDisposable Members
        public void Dispose()
        {
            if (_currentInlineExecution == ContentSecurityPolicyInlineExecution.Hash)
            {
                StringBuilder elementInnerHtmlBuilder = ((StringWriter)_viewContext.Writer).GetStringBuilder();
                string elementInnerHtml = elementInnerHtmlBuilder.ToString();
                string elementHash = ContentSecurityPolicyHelper.ComputeHash(elementInnerHtml);

                _cspHelper.AddHashToInlineExecutionSources(_elementTag.TagName, elementHash);

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
