using System;
using System.Collections.Generic;

namespace SharpDTLS
{
    /// <summary>
    /// record_size_limit (RFC 8449) and max_fragment_length (RFC 6066 §4) negotiation, shared by both engines. Limits
    /// are in payload bytes; in DTLS 1.3 the record_size_limit value also counts the inner content type.
    /// </summary>
    internal static class RecordSizeNegotiation
    {
        private const int Max = TlsConnectionBase.MaxRecordPayload;

        public static void Validate(int? recordSizeLimit, int? maxFragmentLength)
        {
            if (recordSizeLimit is < RecordSizeLimitExtension.Minimum or > Max)
                throw new InvalidOperationException($"RecordSizeLimit must be {RecordSizeLimitExtension.Minimum} to {Max}.");
            if (maxFragmentLength.HasValue)
                _ = new MaxFragmentLengthExtension(maxFragmentLength.Value);
        }

        /// <summary>The client's offer.</summary>
        public static IEnumerable<ITlsExtension> Offer(int? recordSizeLimit, int? maxFragmentLength, bool dtls13)
        {
            Validate(recordSizeLimit, maxFragmentLength);
            if (recordSizeLimit.HasValue)
                yield return new RecordSizeLimitExtension(recordSizeLimit.Value + (dtls13 ? 1 : 0));
            if (maxFragmentLength.HasValue)
                yield return new MaxFragmentLengthExtension(maxFragmentLength.Value);
        }

        /// <summary>
        /// The server's answer to the client's extensions: record_size_limit wins over max_fragment_length when both are
        /// offered (RFC 8449 §5). Returns the limits and the extension to send back, or null.
        /// </summary>
        public static (int Send, int Receive, ITlsExtension Response) Accept(RecordSizeLimitExtension recordSizeLimit,
            MaxFragmentLengthExtension maxFragmentLength, int? ownLimit, bool dtls13)
        {
            if (recordSizeLimit != null)
            {
                int own = ownLimit ?? Max;
                int contentType = dtls13 ? 1 : 0;
                return (Math.Min(recordSizeLimit.Limit - contentType, Max), own, new RecordSizeLimitExtension(own + contentType));
            }
            if (maxFragmentLength != null)
                return (maxFragmentLength.Length, maxFragmentLength.Length, new MaxFragmentLengthExtension(maxFragmentLength.Length));
            return (Max, Max, null);
        }

        /// <summary>The limits from the server's answer to our offer.</summary>
        public static (int Send, int Receive) Complete(RecordSizeLimitExtension recordSizeLimit, MaxFragmentLengthExtension maxFragmentLength,
            int? offeredLimit, int? offeredMaxFragmentLength, bool dtls13)
        {
            if (recordSizeLimit != null && maxFragmentLength != null)
                throw new DtlsException(AlertDescription.IllegalParameter, "Both record_size_limit and max_fragment_length.");
            if (recordSizeLimit != null)
            {
                if (!offeredLimit.HasValue)
                    throw new DtlsException(AlertDescription.UnsupportedExtension, "Unsolicited record_size_limit extension.");
                return (Math.Min(recordSizeLimit.Limit - (dtls13 ? 1 : 0), Max), offeredLimit.Value);
            }
            if (maxFragmentLength != null)
            {
                // RFC 6066 §4: anything but the requested length is illegal_parameter.
                if (offeredMaxFragmentLength != maxFragmentLength.Length)
                    throw new DtlsException(AlertDescription.IllegalParameter, "max_fragment_length differs from the request.");
                return (maxFragmentLength.Length, maxFragmentLength.Length);
            }
            return (Max, Max);
        }
    }
}
