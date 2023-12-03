namespace SW_Pcapng_to_drop_info
{
    public struct UXMapId
    {
        public ulong Value { get; set; }
        public ushort MapId { get; set; }
        public UXMapId(ulong value)
        {
            Value = value;
            MapId = (ushort)((value & 0xFFFFFFFF00000000) >> 32 & 0xFFFF);
        }
    }
}
