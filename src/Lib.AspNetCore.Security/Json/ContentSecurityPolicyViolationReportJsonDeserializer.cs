#if NETCOREAPP3_1 || NET5_0
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security.Json
{
    internal class ContentSecurityPolicyViolationReportJsonDeserializer
    {
        private class ContentSecurityPolicyViolationReportJsonConverter : JsonConverter<ContentSecurityPolicyViolationReport>
        {
            public override ContentSecurityPolicyViolationReport Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                ContentSecurityPolicyViolationReport value = null;

                if (reader.TokenType == JsonTokenType.StartObject)
                {
                    while ((value == null) && reader.Read() && (reader.TokenType != JsonTokenType.EndObject))
                    {
                        if ((reader.TokenType == JsonTokenType.PropertyName) && (reader.GetString() == ContentSecurityPolicyViolationReportPropertyNames.CSP_REPORT))
                        {
                            if (reader.Read() && (reader.TokenType == JsonTokenType.StartObject))
                            {
                                value = new ContentSecurityPolicyViolationReport();

                                while (reader.Read() && (reader.TokenType != JsonTokenType.EndObject))
                                {
                                    if (reader.TokenType == JsonTokenType.PropertyName)
                                    {
                                        string propertyName = reader.GetString();
                                        reader.Read();

                                        switch (propertyName)
                                        {
                                            case ContentSecurityPolicyViolationReportPropertyNames.DOCUMENT_URI:
                                                value.DocumentUri = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.REFERRER:
                                                value.Referrer = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.BLOCKED_URI:
                                                value.BlockedUri = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.EFFECTIVE_DIRECTIVE:
                                                value.EffectiveDirective = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.VIOLATED_DIRECTIVE:
                                                value.ViolatedDirective = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.ORIGINAL_POLICY:
                                                value.Policy = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.DISPOSITION:
                                                value.Disposition = (ContentSecurityPolicyDisposition)Enum.Parse(typeof(ContentSecurityPolicyDisposition), reader.GetString(), true);
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.STATUS_CODE:
                                                value.StatusCode = reader.GetInt32();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.SCRIPT_SAMPLE:
                                                value.Sample = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.SOURCE_FILE:
                                                value.SourceFile = reader.GetString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.LINE_NUMBER:
                                                value.LineNumber = reader.GetInt32();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.COLUMN_NUMBER:
                                                value.ColumnNumber = reader.GetInt32();
                                                break;
                                            default:
                                                break;
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            reader.Skip();
                        }
                    }

                    reader.Read();
                }

                return value;
            }

            public override void Write(Utf8JsonWriter writer, ContentSecurityPolicyViolationReport contentSecurityPolicyViolationReportValue, JsonSerializerOptions options)
            {
                throw new NotSupportedException();
            }
        }

        private static JsonSerializerOptions _jsonSerializerOptions;

        private static JsonSerializerOptions JsonSerializerOptions
        {
            get
            {
                if (_jsonSerializerOptions is null)
                {
                    _jsonSerializerOptions = new JsonSerializerOptions
                    {
                        Converters =
                        {
                            new ContentSecurityPolicyViolationReportJsonConverter()
                        }
                    };
                }

                return _jsonSerializerOptions;
            }
        }

        public static ValueTask<ContentSecurityPolicyViolationReport> DeserializeAsync(Stream json)
        {
            return JsonSerializer.DeserializeAsync<ContentSecurityPolicyViolationReport>(json, JsonSerializerOptions);
        }
    }
}
#endif
