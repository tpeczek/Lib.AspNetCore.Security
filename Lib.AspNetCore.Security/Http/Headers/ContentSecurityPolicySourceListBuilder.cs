using System.Text;
using System.Collections.Generic;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// The source list builder for Content Security Policy directives.
    /// </summary>
    public class ContentSecurityPolicySourceListBuilder
    {
        #region Fields
        private readonly List<string> _withSchemas = new List<string>();
        private readonly List<string> _withUrls = new List<string>();

        private bool _withHttpSchema = false;
        private bool _withHttpsSchema = false;
        private bool _withDataSchema = false;
        private bool _withMediastreamSchema = false;
        private bool _withBlobSchema = false;
        private bool _withFilesystemSchema = false;
        private bool _withSelfKeyword = false;
        private bool _withUnsafeEvalKeyword = false;
        private bool _withUnsafeInlineKeyword = false;
        private bool _withStrictDynamicKeyword = false;

        private const string _sourceSeparator = " ";
        private const string _httpSource = "http" + _sourceSeparator;
        private const string _httpsSource = "https" + _sourceSeparator;
        private const string _dataSource = "data" + _sourceSeparator;
        private const string _mediastreamSource = "mediastream" + _sourceSeparator;
        private const string _blobSource = "blob" + _sourceSeparator;
        private const string _filesystemSource = "filesystem" + _sourceSeparator;
        private const string _selfSource = ContentSecurityPolicyHeaderValue.SelfSource + _sourceSeparator;
        private const string _unsafeEvalSource = ContentSecurityPolicyHeaderValue.UnsafeEvalSource + _sourceSeparator;
        private const string _unsafeInlineSource = "'unsafe-inline'" + _sourceSeparator;
        private const string _strictDynamicSource = "'strict-dynamic'" + _sourceSeparator;
        #endregion

        #region Methods
        /// <summary>
        /// Adds the schemas.
        /// </summary>
        /// <param name="schemas">The schemas.</param>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithSchemas(params string[] schemas)
        {
            _withSchemas.AddRange(schemas);

            return this;
        }

        /// <summary>
        /// Adds the URLs.
        /// </summary>
        /// <param name="urls">The URLs.</param>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithUrls(params string[] urls)
        {
            _withUrls.AddRange(urls);

            return this;
        }

        /// <summary>
        /// Adds the schema to match all http: origins.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithHttpSchema()
        {
            _withHttpSchema = true;

            return this;
        }

        /// <summary>
        /// Adds the schema to match all https: origins.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithHttpsSchema()
        {
            _withHttpsSchema = true;

            return this;
        }

        /// <summary>
        /// Adds the schema to match all data: origins.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithDataSchema()
        {
            _withDataSchema = true;

            return this;
        }

        /// <summary>
        /// Adds the schema to match all mediastream: origins.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithMediastreamSchema()
        {
            _withMediastreamSchema = true;

            return this;
        }

        /// <summary>
        /// Adds the schema to match all blob: origins.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithBlobSchema()
        {
            _withBlobSchema = true;

            return this;
        }

        /// <summary>
        /// Adds the schema to match all filesystem: origins.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithFilesystemSchema()
        {
            _withFilesystemSchema = true;

            return this;
        }
        /// <summary>
        /// Adds the keyword to match current URL’s origin.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithSelfKeyword()
        {
            _withSelfKeyword = true;

            return this;
        }

        /// <summary>
        /// Adds the keyword to allow the use of eval() and similar methods for creating code from strings.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithUnsafeEvalKeyword()
        {
            _withUnsafeEvalKeyword = true;

            return this;
        }

        /// <summary>
        /// Adds the keyword to allow the use of inline resources.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithUnsafeInlineKeyword()
        {
            _withUnsafeInlineKeyword = true;

            return this;
        }

        /// <summary>
        /// Adds the keyword which specifies that the trust explicitly given to a resource present in the markup, by accompanying it with a nonce or a hash, shall be propagated to all the recources loaded by that root resource. At the same time, any whitelist or source expressions such as 'self' or 'unsafe-inline' will be ignored.
        /// </summary>
        /// <returns>The current source list builder.</returns>
        public ContentSecurityPolicySourceListBuilder WithStrictDynamicKeyword()
        {
            _withStrictDynamicKeyword = true;

            return this;
        }

        /// <summary>
        /// Builds a new source list using the settings added.
        /// </summary>
        /// <returns>The constructed source list.</returns>
        public string Build()
        {
            StringBuilder sourceListBuilder = new StringBuilder();

            AppendSources(sourceListBuilder, _withSchemas);
            AppendSources(sourceListBuilder, _withUrls);
            AppendSource(sourceListBuilder, _httpSource, _withHttpSchema);
            AppendSource(sourceListBuilder, _httpsSource, _withHttpsSchema);
            AppendSource(sourceListBuilder, _dataSource, _withDataSchema);
            AppendSource(sourceListBuilder, _mediastreamSource, _withMediastreamSchema);
            AppendSource(sourceListBuilder, _blobSource, _withBlobSchema);
            AppendSource(sourceListBuilder, _filesystemSource, _withFilesystemSchema);
            AppendSource(sourceListBuilder, _selfSource, _withSelfKeyword);
            AppendSource(sourceListBuilder, _unsafeEvalSource, _withUnsafeEvalKeyword);
            AppendSource(sourceListBuilder, _unsafeInlineSource, _withUnsafeInlineKeyword);
            AppendSource(sourceListBuilder, _strictDynamicSource, _withStrictDynamicKeyword);

            if (sourceListBuilder.Length > 0)
            {
                sourceListBuilder.Length--;
            }

            return sourceListBuilder.ToString();
        }

        private static void AppendSource(StringBuilder sourceListBuilder, string source, bool with)
        {
            if (with)
            {
                sourceListBuilder.Append(source);
            }
        }

        private static void AppendSources(StringBuilder sourceListBuilder, IEnumerable<string> sources)
        {
            foreach (string source in sources)
            {
                sourceListBuilder.Append(source).Append(_sourceSeparator);
            }
        }
        #endregion
    }
}
