using System;
using Newtonsoft.Json;
using Lib.AspNetCore.Security.Http.Reports;

namespace Lib.AspNetCore.Security.Json.Converters
{
    internal sealed class ExpectCtViolationReportJsonConverter : JsonConverter
    {
        #region Fields
        private static Type _expectCtViolationReportType = typeof(ExpectCtViolationReport);
        #endregion

        #region Properties
        public override bool CanRead => true;

        public override bool CanWrite => false;
        #endregion

        #region Methods
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
                    if ((reader.TokenType == JsonToken.PropertyName) && ((reader.Value as string) == "expect-ct-report"))
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
                                        case "date-time":
                                            value.FailureDate = reader.ReadAsDateTime() ?? DateTime.MinValue;
                                            break;
                                        case "hostname":
                                            value.Hostname = reader.ReadAsString();
                                            break;
                                        case "port":
                                            value.Port = reader.ReadAsInt32() ?? -1;
                                            break;
                                        case "effective-expiration-date":
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
        #endregion
    }
}
