using System;
using System.Text;
using System.Collections.Generic;

namespace Lib.AspNetCore.Security.Http.Headers
{
    /// <summary>
    /// Policy to selectively enable and disable use of various browser features and APIs.
    /// </summary>
    [Obsolete("Feature Policy has been replaced with Permissions Policy.")]
    public class FeaturePolicy
    {
        #region Fields
        private const string CAMERA_FEATURE = "camera";
        private const string ENCRYPTED_MEDIA_FEATURE = "encrypted-media";
        private const string FULLSCREEN_FEATURE = "fullscreen";
        private const string GEOLOCATION_FEATURE = "geolocation";
        private const string MICROPHONE_FEATURE = "microphone";
        private const string MIDI_FEATURE = "midi";
        private const string PAYMENT_FEATURE = "payment";
        private const string SPEAKER_FEATURE = "speaker";
        private const string VIBRATE_FEATURE = "vibrate";

        private readonly Dictionary<string, string[]> _features = new Dictionary<string, string[]>();

        private string[] _camera, _encryptedMedia, _fullscreen, _geolocation, _microphone, _midi, _payment, _speaker, _vibrate;
        private string _policyDirectiveJson  = null;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to video input devices.
        /// </summary>
        public string[] Camera
        {
            get { return _camera; }

            set
            {
                _policyDirectiveJson = null;
                _camera = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to requestMediaKeySystemAccess().
        /// </summary>
        public string[] EncryptedMedia
        {
            get { return _encryptedMedia; }

            set
            {
                _policyDirectiveJson = null;
                _encryptedMedia = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to requestFullscreen().
        /// </summary>
        public string[] Fullscreen
        {
            get { return _fullscreen; }

            set
            {
                _policyDirectiveJson = null;
                _fullscreen = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to Geolocation interface.
        /// </summary>
        public string[] Geolocation
        {
            get { return _geolocation; }

            set
            {
                _policyDirectiveJson = null;
                _geolocation = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to audio input devices.
        /// </summary>
        public string[] Microphone
        {
            get { return _microphone; }

            set
            {
                _policyDirectiveJson = null;
                _microphone = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to requestMIDIAccess().
        /// </summary>
        public string[] Midi
        {
            get { return _midi; }

            set
            {
                _policyDirectiveJson = null;
                _midi = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to PaymentRequest interface.
        /// </summary>
        public string[] Payment
        {
            get { return _payment; }

            set
            {
                _policyDirectiveJson = null;
                _payment = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to audio output devices.
        /// </summary>
        public string[] Speaker
        {
            get { return _speaker; }

            set
            {
                _policyDirectiveJson = null;
                _speaker = value;
            }
        }

        /// <summary>
        /// Gets or sets the allowlist (the set of allowed origins) for access to vibrate().
        /// </summary>
        public string[] Vibrate
        {
            get { return _vibrate; }

            set
            {
                _policyDirectiveJson = null;
                _vibrate = value;
            }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Sets the feature allowlist (the set of allowed origins).
        /// </summary>
        /// <param name="feature">The feature name.</param>
        /// <param name="allowList">The allowlist (the set of allowed origins).</param>
        public void SetFeatureAllowList(string feature, params string[] allowList)
        {
            _policyDirectiveJson = null;

            switch(feature)
            {
                case CAMERA_FEATURE:
                    _camera = allowList;
                    break;
                case ENCRYPTED_MEDIA_FEATURE:
                    _encryptedMedia = allowList;
                    break;
                case FULLSCREEN_FEATURE:
                    _fullscreen = allowList;
                    break;
                case GEOLOCATION_FEATURE:
                    _geolocation = allowList;
                    break;
                case MICROPHONE_FEATURE:
                    _microphone = allowList;
                    break;
                case MIDI_FEATURE:
                    _midi = allowList;
                    break;
                case PAYMENT_FEATURE:
                    _payment = allowList;
                    break;
                case SPEAKER_FEATURE:
                    _speaker = allowList;
                    break;
                case VIBRATE_FEATURE:
                    _vibrate = allowList;
                    break;
                default:
                    _features[feature] = allowList;
                    break;
            }
        }

        /// <summary>
        /// Gets the feature allowlist (the set of allowed origins).
        /// </summary>
        /// <param name="feature">The feature name.</param>
        /// <returns>The allowlist (the set of allowed origins).</returns>
        public string[] GetFeatureAllowList(string feature)
        {
            string[] featureAllowList = null;

            switch (feature)
            {
                case CAMERA_FEATURE:
                    featureAllowList = _camera;
                    break;
                case ENCRYPTED_MEDIA_FEATURE:
                    featureAllowList = _encryptedMedia;
                    break;
                case FULLSCREEN_FEATURE:
                    featureAllowList = _fullscreen;
                    break;
                case GEOLOCATION_FEATURE:
                    featureAllowList = _geolocation;
                    break;
                case MICROPHONE_FEATURE:
                    featureAllowList = _microphone;
                    break;
                case MIDI_FEATURE:
                    featureAllowList = _midi;
                    break;
                case PAYMENT_FEATURE:
                    featureAllowList = _payment;
                    break;
                case SPEAKER_FEATURE:
                    featureAllowList = _speaker;
                    break;
                case VIBRATE_FEATURE:
                    featureAllowList = _vibrate;
                    break;
                default:
                    featureAllowList = (_features.ContainsKey(feature) ? _features[feature] : null);
                    break;
            }

            return featureAllowList;
        }

        /// <summary>
        /// Serializes the policy to a directive in form of a JSON text (policy-directive-json).
        /// </summary>
        /// <param name="forHttpHeader">The flag indicating if policy is being serialized for HTTP header.</param>
        /// <returns>The policy directive in form of a JSON text (policy-directive-json).</returns>
        public string ToPolicyDirectiveJson(bool forHttpHeader)
        {
            if (_policyDirectiveJson == null)
            {
                StringBuilder policyDirectiveJsonBuilder = new StringBuilder();

                OpenPolicyDirectiveJson(policyDirectiveJsonBuilder, forHttpHeader);

                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, CAMERA_FEATURE, _camera);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, ENCRYPTED_MEDIA_FEATURE, _encryptedMedia);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, FULLSCREEN_FEATURE, _fullscreen);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, GEOLOCATION_FEATURE, _geolocation);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, MICROPHONE_FEATURE, _microphone);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, MIDI_FEATURE, _midi);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, PAYMENT_FEATURE, _payment);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, SPEAKER_FEATURE, _speaker);
                AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, VIBRATE_FEATURE, _vibrate);
                foreach (KeyValuePair<string, string[]> feature in _features)
                {
                    AppendFeatureToPolicyDirectiveJson(policyDirectiveJsonBuilder, feature.Key, feature.Value);
                }

                ClosePolicyDirectiveJson(policyDirectiveJsonBuilder, forHttpHeader);

                _policyDirectiveJson = policyDirectiveJsonBuilder.ToString();
            }

            return _policyDirectiveJson;
        }

        private static StringBuilder OpenPolicyDirectiveJson(StringBuilder policyDirectiveJsonBuilder, bool forHttpHeader)
        {
            if (!forHttpHeader)
            {
                policyDirectiveJsonBuilder.Append("[");
            }

            policyDirectiveJsonBuilder.Append("{");

            return policyDirectiveJsonBuilder;
        }

        private static StringBuilder AppendFeatureToPolicyDirectiveJson(StringBuilder policyDirectiveJsonBuilder, string feature, string[] allowList)
        {
            if (allowList != null)
            {
                policyDirectiveJsonBuilder.AppendFormat("\"{0}\":[", feature);

                foreach (string origin in allowList)
                {
                    policyDirectiveJsonBuilder.AppendFormat("\"{0}\",", origin);
                }

                policyDirectiveJsonBuilder = TrimTrailingComma(policyDirectiveJsonBuilder);

                policyDirectiveJsonBuilder.Append("],");
            }

            return policyDirectiveJsonBuilder;
        }

        private static StringBuilder ClosePolicyDirectiveJson(StringBuilder policyDirectiveJsonBuilder, bool forHttpHeader)
        {
            policyDirectiveJsonBuilder = TrimTrailingComma(policyDirectiveJsonBuilder);

            policyDirectiveJsonBuilder.Append("}");

            if (!forHttpHeader)
            {
                policyDirectiveJsonBuilder.Append("]");
            }

            return policyDirectiveJsonBuilder;
        }

        private static StringBuilder TrimTrailingComma(StringBuilder policyDirectiveJsonBuilder)
        {
            if (policyDirectiveJsonBuilder[policyDirectiveJsonBuilder.Length - 1] == ',')
            {
                policyDirectiveJsonBuilder.Length--;
            }

            return policyDirectiveJsonBuilder;
        }
        #endregion
    }
}
