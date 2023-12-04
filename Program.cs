using Haukcode.PcapngUtils.Common;
using Haukcode.PcapngUtils.PcapNG;
using PacketDotNet;
using System.Text.Json;

namespace SW_Pcapng_to_drop_info
{
    internal class Program
    {
        private static HashSet<string> _ipWhitelist = new();
        private static HashSet<int> _itemBlacklist = new();
        private static readonly List<SoulWorkerDrop> _drops = new();
        private static readonly Dictionary<string, byte[]> _buffers = new();
        private static UXMapId _lastUXMapId = new(0);

        private static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("You must provide a .pcapng file to run this program, press any key to exit...");
                Console.ReadKey();
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("You must provide a valid .pcapng file to run this program, press any key to exit...");
                Console.ReadKey();
                return;
            }

            var whitelistPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "IpWhitelist.txt");
            var blacklistPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ItemBlacklist.txt");

            if (!File.Exists(whitelistPath))
            {
                Console.WriteLine("IP whitelist file isn't present at program directory! Pres any key to exit...");
                Console.ReadKey();
                return;
            }

            var whitelistLines = File.ReadAllLines(whitelistPath);

            _ipWhitelist = whitelistLines.Select(x => x.Trim()).ToHashSet();

            if (File.Exists(blacklistPath))
            {
                var blacklistLines = File.ReadAllLines(blacklistPath);

                _itemBlacklist = blacklistLines.Select(x => int.TryParse(x, out var id) ? id : (int?)null)
                                    .Where(parsedValue => parsedValue.HasValue)
                                    .Select(parsedValue => parsedValue!.Value)
                                    .ToHashSet();
            }

            using var reader = new PcapNGReader(args[0], false);
            
            reader.OnReadPacketEvent += OnReadPacket;
            reader.ReadPackets(CancellationToken.None);
            reader.OnReadPacketEvent -= OnReadPacket;

            var dropDictionary = new Dictionary<ulong, List<SoulWorkerDrop>>();

            foreach (var drop in _drops)
            {
                if (!dropDictionary.ContainsKey(drop.UXMapId))
                {
                    dropDictionary.Add(drop.UXMapId, new List<SoulWorkerDrop>());
                }

                dropDictionary[drop.UXMapId].Add(drop);
            }

            var dumpFileName = $"{Path.GetFileNameWithoutExtension(args[0])}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.json";

            File.WriteAllText(Path.Combine(Directory.GetCurrentDirectory(), dumpFileName), JsonSerializer.Serialize(dropDictionary));

            Console.WriteLine("Finished, press any key to continue...");
            Console.ReadKey();
        }

        private static void OnReadPacket(object context, IPacket packet)
        {
            var parsedPacket = Packet.ParsePacket(LinkLayers.Ethernet, packet.Data);

            var tcpPacket = parsedPacket.Extract<TcpPacket>();

            if (tcpPacket.ParentPacket is not IPv4Packet ipPacket)
            {
                return;
            }

            var packetSourceIp = ipPacket.SourceAddress.ToString();

            if (!_ipWhitelist.Contains(packetSourceIp))
            {
                return;
            }

            if (!tcpPacket.HasPayloadData || tcpPacket.PayloadData.Length < 1)
            {
                return;
            }

            ParsePayload(tcpPacket.PayloadData, packetSourceIp, tcpPacket.SourcePort);
        }

        private static void ParsePayload(byte[] payload, string ip, ushort port)
        {
            var bufferKey = $"{ip}:{port}";

            if (!_buffers.TryGetValue(bufferKey, out var buffer) || buffer.Length < 1)
            {
                buffer = payload;
            } 
            else
            {
                buffer = buffer.Concat(payload).ToArray();
            }

            _buffers.Remove(bufferKey);

            while (true)
            {
                if (buffer.Length < 4)
                {
                    break;
                }

                var packetSize = buffer[2] | (buffer[3] << 8);

                if (buffer.Length < packetSize)
                {
                    break;
                }

                var packetData = buffer.Take(packetSize).ToArray();

                buffer = buffer.Skip(packetSize).ToArray();

                ParseSoulWorkerPacket(packetData);

            }

            if (buffer.Length > 0)
            {
                _buffers.TryAdd(bufferKey, buffer);
            }
        }


        private static void ParseSoulWorkerPacket(byte[] packet)
        {
            var keyIndex = packet[5];
            var payload = packet.Skip(6).ToArray();

            SWCrypt.Decrypt(payload, keyIndex);

            using var ms = new MemoryStream(payload);
            using var reader = new BinaryReader(ms);

            var cmd = reader.ReadByte();
            var subCmd = reader.ReadByte();
            reader.ReadByte(); //skip empty byte, unused

            //World enter
            if (cmd == 0x04 && subCmd == 0x02)
            {
                ms.Position += 0x14;
                _lastUXMapId = new(reader.ReadUInt64());
            }

            //Drop info
            else if (cmd == 0x14 && subCmd == 0x01)
            {
                ms.Position += 5;
                var count = reader.ReadByte();

                for (var i = 0; i < count; i++)
                {
                    reader.ReadSingle(); //x
                    reader.ReadSingle(); //y
                    reader.ReadSingle(); //z

                    var id = reader.ReadInt32();
                    var amount = reader.ReadInt32();
                    ms.Position += 0x0E; //Skip serial and some other info, not needed

                    var drop = new SoulWorkerDrop
                    {
                        ItemId = id,
                        Amount = amount,
                        UXMapId = _lastUXMapId.Value,
                        MapId = _lastUXMapId.MapId                        
                    };

                    if (!_itemBlacklist.Contains(id)) 
                    {
                        Console.WriteLine($"Found drop, Item ID: {drop.ItemId}, Amount: {drop.Amount}, at MapId: {drop.MapId}");

                        _drops.Add(drop);
                    }
                }

            }

        }

    }
}