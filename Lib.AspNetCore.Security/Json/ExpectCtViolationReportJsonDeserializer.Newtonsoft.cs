#if NETSTANDARD2_0
using System;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security.Json
{
    internal class ExpectCtViolationReportJsonDeserializer
    {
        private sealed class ExpectCtViolationReportJsonConverter : JsonConverter
        {
            private static Type _expectCtViolationReportType = typeof(ExpectCtViolationReport);

            public override bool CanRead => true;

            public override bool CanWrite => false;

            public override bool CanConvert(Type objectType)
            {
                return (objectType == _expectCtViolationReportType);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                ExpectCtViolationReport value = null;

                if (reader.TokenType == JsonToken.StartObject)
                {
                    while ((value == null) && reader.Read() && (reader.TokenType != JsonToken.EndObject))
                    {
                        if ((reader.TokenType == JsonToken.PropertyName) && ((reader.Value as string) == ExpectCtViolationReportPropertyNames.EXPECT_CT_REPORT))
                        {
                            if (reader.Read() && (reader.TokenType == JsonToken.StartObject))
                            {
                                value = new ExpectCtViolationReport();

                                while (reader.Read() && (reader.TokenType != JsonToken.EndObject))
                                {
                                    if ((reader.TokenType == JsonToken.PropertyName))
                                    {
                                        switch ((reader.Value as string))
                                        {
                                            case ExpectCtViolationReportPropertyNames.DATE_TIME:
                                                value.FailureDate = reader.ReadAsDateTime() ?? DateTime.MinValue;
                                                break;
                                            case ExpectCtViolationReportPropertyNames.HOSTNAME:
                                                value.Hostname = reader.ReadAsString();
                                                break;
                                            case ExpectCtViolationReportPropertyNames.PORT:
                                                value.Port = reader.ReadAsInt32() ?? -1;
                                                break;
                                            case ExpectCtViolationReportPropertyNames.EFFECTIVE_EXPIRATION_DATE:
                                                value.EffectiveExpirationDate = reader.ReadAsDateTime() ?? DateTime.MinValue;
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

        public static Task<ExpectCtViolationReport> DeserializeAsync(Stream json)
        {
            ExpectCtViolationReport report = null;

            using (StreamReader requestBodyReader = new StreamReader(json))
            {
                using (JsonReader requestBodyJsonReader = new JsonTextReader(requestBodyReader))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    serializer.Converters.Add(new ExpectCtViolationReportJsonConverter());
                    serializer.DateFormatHandling = DateFormatHandling.IsoDateFormat;

                    report = serializer.Deserialize<ExpectCtViolationReport>(requestBodyJsonReader);
                }
            }

            return Task.FromResult(report);
        }
    }
}
#endif
