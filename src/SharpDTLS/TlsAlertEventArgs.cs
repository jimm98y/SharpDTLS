using System;

namespace SharpDTLS
{
    /// <summary>An alert received on one of a server's connections.</summary>
    public class TlsAlertEventArgs : EventArgs
    {
        public TlsAlertEventArgs(TlsConnectionBase connection, AlertDescription description)
        {
            Connection = connection;
            Description = description;
        }

        /// <summary>The connection the alert arrived on; its RemoteEndPoint identifies the peer.</summary>
        public TlsConnectionBase Connection { get; }
        public AlertDescription Description { get; }
    }
}
