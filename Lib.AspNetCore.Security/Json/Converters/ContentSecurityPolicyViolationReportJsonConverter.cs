using System;
using Newtonsoft.Json;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security.Json.Converters
{
    internal sealed class ContentSecurityPolicyViolationReportJsonConverter : JsonConverter
    {
        #region Fields
        private static Type _contentSecurityPolicyViolationReportType = typeof(ContentSecurityPolicyViolationReport);
        #endregion

        #region Properties
        public override bool CanRead => true;

        public override bool CanWrite => false;
        #endregion

        #region Methods
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
                    if ((reader.TokenType == JsonToken.PropertyName) && ((reader.Value as string) == "csp-report"))
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
                                        case "document-uri":
                                            value.DocumentUri = reader.ReadAsString();
                                            break;
                                        case "referrer":
                                            value.Referrer = reader.ReadAsString();
                                            break;
                                        case "blocked-uri":
                                            value.BlockedUri = reader.ReadAsString();
                                            break;
                                        case "effective-directive":
                                            value.EffectiveDirective = reader.ReadAsString();
                                            break;
                                        case "violated-directive":
                                            value.ViolatedDirective = reader.ReadAsString();
                                            break;
                                        case "original-policy":
                                            value.Policy = reader.ReadAsString();
                                            break;
                                        case "disposition":
                                            value.Disposition = (ContentSecurityPolicyDisposition)Enum.Parse(typeof(ContentSecurityPolicyDisposition), reader.ReadAsString(), true);
                                            break;
                                        case "status-code":
                                            value.StatusCode = reader.ReadAsInt32() ?? 0;
                                            break;
                                        case "script-sample":
                                            value.Sample = reader.ReadAsString();
                                            break;
                                        case "source-file":
                                            value.SourceFile = reader.ReadAsString();
                                            break;
                                        case "line-number":
                                            value.LineNumber = reader.ReadAsInt32();
                                            break;
                                        case "column-number":
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
        #endregion
    }
}
