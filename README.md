<p align="center"><img width="400" height="300" alt="logo" src="https://github.com/user-attachments/assets/adeef2ed-aab3-4bf7-aa8d-ab3233ff6bdc" /></p>

A simple ARP spoofing tool written in C# for Windows/Linux environments.  
Designed for ethical hacking and penetration testing purposes.

---

## Features

- List all network interfaces and select one to attack
- Discover gateway MAC address automatically
- Attempt to retrieve target MAC address by IP
- Simple console interface with clear messages
- Written in C#

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/joaostack/ArpSpoof.git
cd ArpSpoof
```

2. Restore dependencies:

```bash
dotnet restore
```

---

## Usage

Help Menu
```bash
sudo dotnet run --project src -- -h
```

Run the project with `sudo` (required for raw packet sending):

```bash
sudo dotnet run --project src -- --target-address <TARGET_IP> --gateway-address <GATEWAY_IP>
```

Example:

```bash
sudo dotnet run --project src -- --target-address 192.168.2.221 --gateway-address 192.168.2.1
```

You will be prompted to select a network interface.  
The program will attempt to discover MAC addresses and start spoofing.

## Demo 1
<img width="481" height="315" alt="Screenshot_20250819_134945" src="https://github.com/user-attachments/assets/b32f64bf-9b21-4e4e-9616-9b6474bcd5bc" />

## Demo 2
<img width="783" height="201" alt="Screenshot_20250819_140537" src="https://github.com/user-attachments/assets/8084d121-c2d9-4ab5-8ea8-03d664044a21" />

---

## Dependencies

- [.NET SDK](https://dotnet.microsoft.com/en-us/download)
- [SharpPcap](https://github.com/chmorgan/sharppcap)
- [System.CommandLine](https://github.com/dotnet/command-line-api)

---

## Contributing

Feel free to open issues, submit bug reports, or suggest improvements.  
Please respect ethical hacking principles and only test in environments you own or have permission to test.

Donations
**Monero (XMR)**
```
4BE47AD2o1QFu2oq1HEx6i9QBM2xcMaMGSc4vdW9sPZz8LNNue9DZqqiagR9KbQndYgNNTmDjXY87CdQTETAFmAgSSjAEQj
```

---

## Author

<b>João H.</b> (joaostack) – [GitHub](https://github.com/joaostack)





