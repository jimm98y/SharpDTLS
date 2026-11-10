// SharpDTLS
// Copyright (C) 2026 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using System;
using System.Threading;

namespace SharpDTLS
{
    /// <summary>
    /// Handshake retransmission timer with exponential back-off (RFC 6347 §4.2.4, RFC 9147 §5.8):
    /// starts at the initial timeout, doubles on every expiry up to 60 s, and gives up after
    /// <see cref="MaxRetransmissions"/> expiries. Callbacks run on a thread-pool thread.
    /// </summary>
    internal sealed class RetransmitTimer : IDisposable
    {
        public const int MaxRetransmissions = 8;
        private static readonly TimeSpan MaxTimeout = TimeSpan.FromSeconds(60);

        private readonly object _sync = new object();
        private readonly Action _retransmit;
        private readonly Action _giveUp;
        private Timer _timer;
        private TimeSpan _current;
        private int _count;

        public RetransmitTimer(Action retransmit, Action giveUp)
        {
            _retransmit = retransmit;
            _giveUp = giveUp;
        }

        public bool IsRunning { get { lock (_sync) return _timer != null; } }

        public void Start(TimeSpan initialTimeout)
        {
            lock (_sync)
            {
                _timer?.Dispose();
                _count = 0;
                _current = initialTimeout;
                _timer = new Timer(OnTimer, null, _current, Timeout.InfiniteTimeSpan);
            }
        }

        public void Stop()
        {
            lock (_sync)
            {
                _timer?.Dispose();
                _timer = null;
            }
        }

        private void OnTimer(object state)
        {
            bool giveUp;
            lock (_sync)
            {
                if (_timer == null)
                    return;
                giveUp = ++_count > MaxRetransmissions;
                if (giveUp)
                {
                    _timer.Dispose();
                    _timer = null;
                }
                else
                {
                    _current = TimeSpan.FromTicks(Math.Min(_current.Ticks * 2, MaxTimeout.Ticks));
                    _timer.Change(_current, Timeout.InfiniteTimeSpan);
                }
            }

            try
            {
                if (giveUp) _giveUp();
                else _retransmit();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Retransmission callback failed: {ex.Message}");
            }
        }

        public void Dispose() => Stop();
    }
}
