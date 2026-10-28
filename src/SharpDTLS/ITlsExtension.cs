using System;
using System.Collections.Generic;
using System.Text;

namespace SharpDTLS
{
    internal interface ITlsExtension
    {
        int Write(int offset, byte[] destination);
        int Read(int offset, byte[] source);
        int CalculateLength();
    }
}
