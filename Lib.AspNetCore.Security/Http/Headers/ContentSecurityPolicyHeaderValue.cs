using System;
using System.Text;
using System.Collections.Generic;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Content Security Policy require SRI options.
    /// </summary>
    [Flags]
    public enum ContentSecurityPolicyRequireSriFor
    {
        /// <summary>
        /// Requires SRI for scripts.
        /// </summary>
        Script = 0,
        /// <summary>
        /// Requires SRI for style sheets.
        /// </summary>
        Style = 1
    }

    /// <summary>
    /// Content Security Policy sandbox flags.
    /// </summary>
    [Flags]
    public enum ContentSecurityPolicySandboxFlags
    {
        /// <summary>
        /// Set no sandbox flags
        /// </summary>
        None = 0,
        /// <summary>
        /// Set allow-forms sandbox flag
        /// </summary>
        AllowForms = 1,
        /// <summary>
        /// Set allow-pointer-lock sandbox flag
        /// </summary>
        AllowPointerLock = 2,
        /// <summary>
        /// Set allow-popups sandbox flag
        /// </summary>
        AllowPopups = 4,
        /// <summary>
        /// Set allow-same-origin sandbox flag
        /// </summary>
        AllowSameOrigin = 8,
        /// <summary>
        /// Set allow-scripts sandbox flag
        /// </summary>
        AllowScripts = 16,
        /// <summary>
        /// Set allow-top-navigation sandbox flag
        /// </summary>
        AllowTopNavigation = 32
    }

    /// <summary>
    /// Content Security Policy inline execution modes.
    /// </summary>
    public enum ContentSecurityPolicyInlineExecution
    {
        /// <summary>
        /// Refuse any inline execution
        /// </summary>
        Refuse,
        /// <summary>
        /// Allow all inline execution
        /// </summary>
        Unsafe,
        /// <summary>
        /// Use nonce mechanism
        /// </summary>
        Nonce,
        /// <summary>
        /// Use hash mechanism (SHA-256)
        /// </summary>
        Hash,
        /// <summary>
        /// Use hash mechanism (SHA-384)
        /// </summary>
        Hash384,
        /// <summary>
        /// Use hash mechanism (SHA-512)
        /// </summary>
        Hash512
    }

    /// <summary>
    /// Extensions for <see cref="ContentSecurityPolicyInlineExecution"/>.
    /// </summary>
    public static class ContentSecurityPolicyInlineExecutionExtensions
    {
        /// <summary>
        /// Returns value indicating if inline execution mode is one of hash based ones.
        /// </summary>
        /// <param name="inlineExecution">The inline execution mode.</param>
        /// <returns>True if inline execution mode is hash based, otherwise false.</returns>
        public static bool IsHashBased(this ContentSecurityPolicyInlineExecution inlineExecution)
        {
            return (inlineExecution == ContentSecurityPolicyInlineExecution.Hash)
                || (inlineExecution == ContentSecurityPolicyInlineExecution.Hash384)
                || (inlineExecution == ContentSecurityPolicyInlineExecution.Hash512);
        }
    }

    /// <summary>
    /// Represents value of Content-Security-Policy or Content-Security-Policy-Report-Only header.
    /// </summary>
    public class ContentSecurityPolicyHeaderValue
    {
        #region Fields
        /// <summary>
        /// The source list keyword to match nothing.
        /// </summary>
        public const string NoneSource = "'none'";

        /// <summary>
        /// The source list keyword to match current URL’s origin.
        /// </summary>
        public const string SelfSource = "'self'";

        /// <summary>
        /// The source list keyword to allow the use of eval() and similar methods for creating code from strings.
        /// </summary>
        public const string UnsafeEvalSource = "'unsafe-eval'";

        private const string _baseDirectiveFormat = "base-uri {0};";
        private const string _blockAllMixedContentDirective = "block-all-mixed-content;";
        private const string _childDirectiveFormat = "child-src {0};";
        private const string _connectDirectiveFormat = "connect-src {0};";
        private const string _defaultDirectiveFormat = "default-src {0};";
        private const string _fontDirectiveFormat = "font-src {0};";
        private const string _formDirectiveFormat = "form-action {0};";
        private const string _frameAncestorsDirectiveFormat = "frame-ancestors {0};";
        private const string _frameDirectiveFormat = "frame-src {0};";
        private const string _imageDirectiveFormat = "img-src {0};";
        private const string _manifestDirectiveFormat = "manifest-src {0};";
        private const string _mediaDirectiveFormat = "media-src {0};";
        private const string _objectDirectiveFormat = "object-src {0};";
        private const string _pluginTypesDirectiveFormat = "plugin-types {0};";
        private const string _reportDirectiveFormat = "report-uri {0};";
        private const string _requireSriForDirective = "require-sri-for";
        private const string _sandboxDirective = "sandbox";
        private const string _scriptDirective = "script-src";
        private const string _styleDirective = "style-src";
        private const string _upgradeInsecureRequestsDirective = "upgrade-insecure-requests;";
        private const string _workerDirectiveFormat = "worker-src {0};";
        private const string _directiveDelimiter = ";";

        private const string _allowFormsSandboxFlag = " allow-forms";
        private const string _allowPointerLockSandboxFlag = " allow-pointer-lock";
        private const string _allowPopupsSandboxFlag = " allow-popups";
        private const string _allowSameOriginSandboxFlag = " allow-same-origin";
        private const string _allowScriptsSandboxFlag = " allow-scripts";
        private const string _allowTopNavigationSandboxFlag = " allow-top-navigation";

        private const string _unsafeInlineSource = " 'unsafe-inline'";
        private const string _nonceSourceFormat = " 'nonce-{0}'";
        private const string _hashSourceFormat = " '{0}'";

        private string _baseUri, _childSources, _connectSources, _defaultSources, _fontSources, _formAction, _frameAncestorsSources, _frameSources;
        private string _imageSources, _manifestSources, _mediaSources, _objectSources, _pluginTypes, _reportUri, _scriptSources, _styleSources, _workerSources;
        private bool _blockAllMixedContent, _sandbox, _upgradeInsecureRequests;
        private ContentSecurityPolicyRequireSriFor? _requireSriFor;
        private ContentSecurityPolicySandboxFlags _sandboxFlags;
        private ContentSecurityPolicyInlineExecution _scriptInlineExecution, _styleInlineExecution;

        private string _completeRequireSriForDirective = null;
        private string _completeSandboxDirective = null;
        private string _headerValue = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the list of URLs that can be used to specify the document base URL.
        /// </summary>
        public string BaseUri
        {
            get { return _baseUri; }

            set
            {
                _headerValue = null;
                _baseUri = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if block-all-mixed-content directive should be included.
        /// </summary>
        public bool BlockAllMixedContent
        {
            get { return _blockAllMixedContent; }

            set
            {
                _headerValue = null;
                _blockAllMixedContent = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for web workers and nested browsing contexts.
        /// </summary>
        public string ChildSources
        {
            get { return _childSources; }

            set
            {
                _headerValue = null;
                _childSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for fetch, XMLHttpRequest, WebSocket, and EventSource connections.
        /// </summary>
        public string ConnectSources
        {
            get { return _connectSources; }

            set
            {
                _headerValue = null;
                _connectSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the default source list for directives which can fall back to the default sources.
        /// </summary>
        public string DefaultSources
        {
            get { return _defaultSources; }

            set
            {
                _headerValue = null;
                _defaultSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for fonts loaded using @font-face.
        /// </summary>
        public string FontSources
        {
            get { return _fontSources; }

            set
            {
                _headerValue = null;
                _fontSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the valid endpoints for form submissions.
        /// </summary>
        public string FormAction
        {
            get { return _formAction; }

            set
            {
                _headerValue = null;
                _formAction = value;
            }
        }

        /// <summary>
        /// Gets or sets the valid parents that may embed a page using the frame and iframe elements.
        /// </summary>
        public string FrameAncestorsSources
        {
            get { return _frameAncestorsSources; }

            set
            {
                _headerValue = null;
                _frameAncestorsSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for nested browsing contexts loading using elements such as frame and iframe.
        /// </summary>
        public string FrameSources
        {
            get { return _frameSources; }

            set
            {
                _headerValue = null;
                _frameSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for of images and favicons.
        /// </summary>
        public string ImageSources
        {
            get { return _imageSources; }

            set
            {
                _headerValue = null;
                _imageSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for manifest which can be applied to the resource.
        /// </summary>
        public string ManifestSources
        {
            get { return _manifestSources; }

            set
            {
                _headerValue = null;
                _manifestSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for loading media using the audio and video elements.
        /// </summary>
        public string MediaSources
        {
            get { return _mediaSources; }

            set
            {
                _headerValue = null;
                _mediaSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for the object, embed, and applet elements.
        /// </summary>
        public string ObjectSources
        {
            get { return _objectSources; }

            set
            {
                _headerValue = null;
                _objectSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the types of plugins that can be embedded into a document.
        /// </summary>
        public string PluginTypes
        {
            get { return _pluginTypes; }

            set
            {
                _headerValue = null;
                _pluginTypes = value;
            }
        }

        /// <summary>
        /// Gets or sets the URL to which the user agent should send reports about policy violations.
        /// </summary>
        public string ReportUri
        {
            get { return _reportUri; }

            set
            {
                _headerValue = null;
                _reportUri = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if the use of Subresource Integrity is required for scripts or/and styles.
        /// </summary>
        public ContentSecurityPolicyRequireSriFor? RequireSriFor
        {
            get { return _requireSriFor; }

            set
            {
                _headerValue = null;
                _completeRequireSriForDirective = null;
                _requireSriFor = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if sandbox policy should be applied.
        /// </summary>
        public bool Sandbox
        {
            get { return _sandbox; }

            set
            {
                _headerValue = null;
                _completeSandboxDirective = null;
                _sandbox = value;
            }
        }

        /// <summary>
        /// Gets or sets the sandboxing flags (only used when Sandbox is true).
        /// </summary>
        public ContentSecurityPolicySandboxFlags SandboxFlags
        {
            get { return _sandboxFlags; }

            set
            {
                _headerValue = null;
                _completeSandboxDirective = null;
                _sandboxFlags = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for scripts.
        /// </summary>
        public string ScriptSources
        {
            get { return _scriptSources; }

            set
            {
                _headerValue = null;
                _scriptSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the inline execution mode for scripts.
        /// </summary>
        public ContentSecurityPolicyInlineExecution ScriptInlineExecution
        {
            get { return _scriptInlineExecution; }

            set
            {
                _headerValue = null;
                _scriptInlineExecution = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for stylesheets.
        /// </summary>
        public string StyleSources
        {
            get { return _styleSources; }

            set
            {
                _headerValue = null;
                _styleSources = value;
            }
        }

        /// <summary>
        /// Gets or sets the inline execution mode for stylesheets.
        /// </summary>
        public ContentSecurityPolicyInlineExecution StyleInlineExecution
        {
            get { return _styleInlineExecution; }

            set
            {
                _headerValue = null;
                _styleInlineExecution = value;
            }
        }

        /// <summary>
        /// Gets or sets the value indicating if upgrade-insecure-requests directive should be included.
        /// </summary>
        public bool UpgradeInsecureRequests
        {
            get { return _upgradeInsecureRequests; }

            set
            {
                _headerValue = null;
                _upgradeInsecureRequests = value;
            }
        }

        /// <summary>
        /// Gets or sets the source list for Worker, SharedWorker, or ServiceWorker scripts.
        /// </summary>
        public string WorkerSources
        {
            get { return _workerSources; }

            set
            {
                _headerValue = null;
                _workerSources = value;
            }
        }

        private bool CanCacheHeaderValue
        {
            get
            {
                return ((_scriptInlineExecution == ContentSecurityPolicyInlineExecution.Refuse) || (_scriptInlineExecution == ContentSecurityPolicyInlineExecution.Unsafe))
                    && ((_styleInlineExecution == ContentSecurityPolicyInlineExecution.Refuse) || (_styleInlineExecution == ContentSecurityPolicyInlineExecution.Unsafe));
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Instantiates a new <see cref="ContentSecurityPolicyHeaderValue"/>.
        /// </summary>
        public ContentSecurityPolicyHeaderValue()
        {
            _blockAllMixedContent = false;
            _defaultSources = NoneSource;
            _sandbox = false;
            _sandboxFlags = ContentSecurityPolicySandboxFlags.None;
            _scriptInlineExecution = ContentSecurityPolicyInlineExecution.Refuse;
            _styleInlineExecution = ContentSecurityPolicyInlineExecution.Refuse;
            _upgradeInsecureRequests = false;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <returns>The string representation of header value.</returns>
        public override string ToString()
        {
            return ToString(null, null, null);
        }

        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <param name="nonce">The nonce to be used for inline execution source lists.</param>
        /// <returns>The string representation of header value.</returns>
        public string ToString(string nonce)
        {
            return ToString(nonce, null, null);
        }

        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <param name="scriptsHashes">The inline scripts hashes for inline execution source list.</param>
        /// <param name="stylesHashes">The inline styles hashes for inline execution source list.</param>
        /// <returns>The string representation of header value.</returns>
        public string ToString(IEnumerable<string> scriptsHashes, IEnumerable<string> stylesHashes)
        {
            return ToString(null, scriptsHashes, stylesHashes);
        }

        /// <summary>
        /// Gets the string representation of header value.
        /// </summary>
        /// <param name="nonce">The nonce to be used for inline execution source lists.</param>
        /// <param name="scriptsHashes">The inline scripts hashes for inline execution source list.</param>
        /// <param name="stylesHashes">The inline styles hashes for inline execution source list.</param>
        /// <returns>The string representation of header value.</returns>
        public string ToString(string nonce, IEnumerable<string> scriptsHashes, IEnumerable<string> stylesHashes)
        {
            string headerValue = _headerValue;

            if (headerValue == null)
            {
                StringBuilder headerValueBuilder = new StringBuilder();

                AppendHeaderValueDirective(headerValueBuilder, _baseDirectiveFormat, _baseUri);
                AppendHeaderValueDirective(headerValueBuilder, _childDirectiveFormat, _childSources);
                AppendHeaderValueDirective(headerValueBuilder, _connectDirectiveFormat, _connectSources);
                AppendHeaderValueDirective(headerValueBuilder, _defaultDirectiveFormat, _defaultSources);
                AppendHeaderValueDirective(headerValueBuilder, _fontDirectiveFormat, _fontSources);
                AppendHeaderValueDirective(headerValueBuilder, _formDirectiveFormat, _formAction);
                AppendHeaderValueDirective(headerValueBuilder, _frameAncestorsDirectiveFormat, _frameAncestorsSources);
                AppendHeaderValueDirective(headerValueBuilder, _frameDirectiveFormat, _frameSources);
                AppendHeaderValueDirective(headerValueBuilder, _imageDirectiveFormat, _imageSources);
                AppendHeaderValueDirective(headerValueBuilder, _manifestDirectiveFormat, _manifestSources);
                AppendHeaderValueDirective(headerValueBuilder, _mediaDirectiveFormat, _mediaSources);
                AppendHeaderValueDirective(headerValueBuilder, _objectDirectiveFormat, _objectSources);
                AppendHeaderValueDirective(headerValueBuilder, _pluginTypesDirectiveFormat, _pluginTypes);
                AppendHeaderValueDirective(headerValueBuilder, _reportDirectiveFormat, _reportUri);
                AppendHeaderValueRequireSriForDirective(headerValueBuilder);
                AppendHeaderValueSandboxDirective(headerValueBuilder);
                AppendHeaderValueDirectiveWithInlineExecution(headerValueBuilder, _scriptDirective, _scriptSources, _scriptInlineExecution, nonce, scriptsHashes);
                AppendHeaderValueDirectiveWithInlineExecution(headerValueBuilder, _styleDirective, _styleSources, _styleInlineExecution, nonce, stylesHashes);
                AppendHeaderValueDirective(headerValueBuilder, _workerDirectiveFormat, _workerSources);

                if (_upgradeInsecureRequests)
                {
                    headerValueBuilder.Append(_upgradeInsecureRequestsDirective);
                }
                else if (_blockAllMixedContent)
                {
                    headerValueBuilder.Append(_blockAllMixedContentDirective);
                }

                headerValue = headerValueBuilder.ToString();

                if (CanCacheHeaderValue)
                {
                    _headerValue = headerValue;
                }
            }

            return headerValue;
        }

        private static void AppendHeaderValueDirective(StringBuilder headerValueBuilder, string directiveFormat, string directiveValue)
        {
            if (!String.IsNullOrWhiteSpace(directiveValue))
            {
                headerValueBuilder.AppendFormat(directiveFormat, directiveValue);
            }
        }

        private void AppendHeaderValueRequireSriForDirective(StringBuilder headerValueBuilder)
        {
            if (String.IsNullOrWhiteSpace(_completeRequireSriForDirective))
            {
                if (_requireSriFor.HasValue)
                {
                    int completeRequireSriForDirectiveStartIndex = headerValueBuilder.Length;
                    headerValueBuilder.Append(_requireSriForDirective);

                    foreach (ContentSecurityPolicyRequireSriFor requireSriFor in Enum.GetValues(typeof(ContentSecurityPolicyRequireSriFor)))
                    {
                        if (_requireSriFor.Value.HasFlag(requireSriFor))
                        {
                            headerValueBuilder.Append(" ").Append(requireSriFor.ToString().ToLowerInvariant());
                        }
                    }

                    headerValueBuilder.Append(_directiveDelimiter);
                    _completeRequireSriForDirective = headerValueBuilder.ToString(completeRequireSriForDirectiveStartIndex, headerValueBuilder.Length - completeRequireSriForDirectiveStartIndex);
                }
            }
            else
            {
                headerValueBuilder.Append(_completeRequireSriForDirective);
            }
        }

        private void AppendHeaderValueSandboxDirective(StringBuilder headerValueBuilder)
        {
            if (String.IsNullOrWhiteSpace(_completeSandboxDirective))
            {
                if (_sandbox)
                {
                    int completeSandboxDirectiveStartIndex = headerValueBuilder.Length;
                    headerValueBuilder.Append(_sandboxDirective);

                    if (_sandboxFlags != ContentSecurityPolicySandboxFlags.None)
                    {
                        AppendSandboxDirectiveFlag(headerValueBuilder, ContentSecurityPolicySandboxFlags.AllowForms, _allowFormsSandboxFlag);
                        AppendSandboxDirectiveFlag(headerValueBuilder, ContentSecurityPolicySandboxFlags.AllowPointerLock, _allowPointerLockSandboxFlag);
                        AppendSandboxDirectiveFlag(headerValueBuilder, ContentSecurityPolicySandboxFlags.AllowPopups, _allowPopupsSandboxFlag);
                        AppendSandboxDirectiveFlag(headerValueBuilder, ContentSecurityPolicySandboxFlags.AllowSameOrigin, _allowSameOriginSandboxFlag);
                        AppendSandboxDirectiveFlag(headerValueBuilder, ContentSecurityPolicySandboxFlags.AllowScripts, _allowScriptsSandboxFlag);
                        AppendSandboxDirectiveFlag(headerValueBuilder, ContentSecurityPolicySandboxFlags.AllowTopNavigation, _allowTopNavigationSandboxFlag);
                    }

                    headerValueBuilder.Append(_directiveDelimiter);
                    _completeSandboxDirective = headerValueBuilder.ToString(completeSandboxDirectiveStartIndex, headerValueBuilder.Length - completeSandboxDirectiveStartIndex);
                }
            }
            else
            {
                headerValueBuilder.Append(_completeSandboxDirective);
            }
        }

        private void AppendSandboxDirectiveFlag(StringBuilder headerValueBuilder, ContentSecurityPolicySandboxFlags flag, string flagValue)
        {
            if (_sandboxFlags.HasFlag(flag))
            {
                headerValueBuilder.Append(flagValue);
            }
        }

        private void AppendHeaderValueDirectiveWithInlineExecution(StringBuilder headerValueBuilder, string directiveName, string directiveValue, ContentSecurityPolicyInlineExecution inlineExecution, string nonce, IEnumerable<string> hashes)
        {
            if (!String.IsNullOrWhiteSpace(directiveValue) || (inlineExecution != ContentSecurityPolicyInlineExecution.Refuse))
            {
                headerValueBuilder.Append(directiveName);

                if (!String.IsNullOrWhiteSpace(directiveValue))
                {
                    headerValueBuilder.AppendFormat(" {0}", directiveValue);
                }

                if (inlineExecution == ContentSecurityPolicyInlineExecution.Unsafe)
                {
                    headerValueBuilder.Append(_unsafeInlineSource);
                }
                else if (inlineExecution == ContentSecurityPolicyInlineExecution.Nonce)
                {
                    if (String.IsNullOrWhiteSpace(nonce))
                    {
                        throw new InvalidOperationException("Nonce mode for Content Security Policy inline execution requires providing nonce value.");
                    }

                    headerValueBuilder.AppendFormat(_nonceSourceFormat, nonce);
                }
                else if (inlineExecution.IsHashBased() && (hashes != null))
                {
                    foreach (string inlineHash in hashes)
                    {
                        headerValueBuilder.AppendFormat(_hashSourceFormat, inlineHash);
                    }
                }

                headerValueBuilder.Append(_directiveDelimiter);
            }
        }
        #endregion
    }
}
