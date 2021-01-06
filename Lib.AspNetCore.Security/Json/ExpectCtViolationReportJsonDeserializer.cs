#if NETCOREAPP3_1 || NET5_0
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security.Json
{
    internal class ExpectCtViolationReportJsonDeserializer
    {
        private class ExpectCtViolationReportJsonConverter : JsonConverter<ExpectCtViolationReport>
        {
            public override ExpectCtViolationReport Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                ExpectCtViolationReport value = null;

                if (reader.TokenType == JsonTokenType.StartObject)
                {
                    while ((value == null) && reader.Read() && (reader.TokenType != JsonTokenType.EndObject))
                    {
                        if ((reader.TokenType == JsonTokenType.PropertyName) && (reader.GetString() == ExpectCtViolationReportPropertyNames.EXPECT_CT_REPORT))
                        {
                            if (reader.Read() && (reader.TokenType == JsonTokenType.StartObject))
                            {
                                value = new ExpectCtViolationReport();

                                while (reader.Read() && (reader.TokenType != JsonTokenType.EndObject))
                                {
                                    if (reader.TokenType == JsonTokenType.PropertyName)
                                    {
                                        string propertyName = reader.GetString();
                                        reader.Read();

                                        switch (propertyName)
                                        {
                                            case ExpectCtViolationReportPropertyNames.DATE_TIME:
                                                value.FailureDate = reader.GetDateTime();
                                                break;
                                            case ExpectCtViolationReportPropertyNames.HOSTNAME:
                                                value.Hostname = reader.GetString();
                                                break;
                                            case ExpectCtViolationReportPropertyNames.PORT:
                                                value.Port = reader.GetInt32();
                                                break;
                                            case ExpectCtViolationReportPropertyNames.EFFECTIVE_EXPIRATION_DATE:
                                                value.EffectiveExpirationDate = reader.GetDateTime();
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

            public override void Write(Utf8JsonWriter writer, ExpectCtViolationReport expectCtViolationReportValue, JsonSerializerOptions options)
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
                            new ExpectCtViolationReportJsonConverter()
                        }
                    };
                }

                return _jsonSerializerOptions;
            }
        }

        public static ValueTask<ExpectCtViolationReport> DeserializeAsync(Stream json)
        {
            return JsonSerializer.DeserializeAsync<ExpectCtViolationReport>(json, JsonSerializerOptions);
        }
    }
}
#endif
