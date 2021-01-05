#if NETSTANDARD2_0
using System;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security.Json
{
    internal class ContentSecurityPolicyViolationReportJsonDeserializer
    {
        private sealed class ContentSecurityPolicyViolationReportJsonConverter : JsonConverter
        {
            private static Type _contentSecurityPolicyViolationReportType = typeof(ContentSecurityPolicyViolationReport);

            public override bool CanRead => true;

            public override bool CanWrite => false;

            public override bool CanConvert(Type objectType)
            {
                return (objectType == _contentSecurityPolicyViolationReportType);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                ContentSecurityPolicyViolationReport value = null;

                if (reader.TokenType == JsonToken.StartObject)
                {
                    while ((value == null) && reader.Read() && (reader.TokenType != JsonToken.EndObject))
                    {
                        if ((reader.TokenType == JsonToken.PropertyName) && ((reader.Value as string) == ContentSecurityPolicyViolationReportPropertyNames.CSP_REPORT))
                        {
                            if (reader.Read() && (reader.TokenType == JsonToken.StartObject))
                            {
                                value = new ContentSecurityPolicyViolationReport();

                                while (reader.Read() && (reader.TokenType != JsonToken.EndObject))
                                {
                                    if ((reader.TokenType == JsonToken.PropertyName))
                                    {
                                        switch ((reader.Value as string))
                                        {
                                            case ContentSecurityPolicyViolationReportPropertyNames.DOCUMENT_URI:
                                                value.DocumentUri = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.REFERRER:
                                                value.Referrer = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.BLOCKED_URI:
                                                value.BlockedUri = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.EFFECTIVE_DIRECTIVE:
                                                value.EffectiveDirective = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.VIOLATED_DIRECTIVE:
                                                value.ViolatedDirective = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.ORIGINAL_POLICY:
                                                value.Policy = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.DISPOSITION:
                                                value.Disposition = (ContentSecurityPolicyDisposition)Enum.Parse(typeof(ContentSecurityPolicyDisposition), reader.ReadAsString(), true);
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.STATUS_CODE:
                                                value.StatusCode = reader.ReadAsInt32() ?? 0;
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.SCRIPT_SAMPLE:
                                                value.Sample = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.SOURCE_FILE:
                                                value.SourceFile = reader.ReadAsString();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.LINE_NUMBER:
                                                value.LineNumber = reader.ReadAsInt32();
                                                break;
                                            case ContentSecurityPolicyViolationReportPropertyNames.COLUMN_NUMBER:
                                                value.ColumnNumber = reader.ReadAsInt32();
                                                break;
                                            default:
                                                reader.Skip();
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
                }

                return value;
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                throw new NotImplementedException();
            }
        }

        public static Task<ContentSecurityPolicyViolationReport> DeserializeAsync(Stream json)
        {
            ContentSecurityPolicyViolationReport report = null;

            using (StreamReader requestBodyReader = new StreamReader(json))
            {
                using (JsonReader requestBodyJsonReader = new JsonTextReader(requestBodyReader))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    serializer.Converters.Add(new ContentSecurityPolicyViolationReportJsonConverter());

                    report = serializer.Deserialize<ContentSecurityPolicyViolationReport>(requestBodyJsonReader);
                }
            }

            return Task.FromResult(report);
        }
    }
}
#endif