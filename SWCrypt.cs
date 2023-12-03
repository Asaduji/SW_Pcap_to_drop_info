using System.Runtime.InteropServices;

namespace SW_Pcapng_to_drop_info
{
    public class SWCrypt
    {

        [DllImport("SWCryptWrapper.dll")]
        private static extern void Decrypt(byte[] packet, int size, int keyIndex);

        public static void Decrypt(byte[] packet, int keyIndex)
        {
            Decrypt(packet, packet.Length, keyIndex);
        }
    }
}
