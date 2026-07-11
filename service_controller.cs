using System;
using System.ServiceProcess;
using System.Security.Principal;
using System.Diagnostics;
using System.IO;

namespace NetVisorServiceController
{
    class Program
    {
        static void Main(string[] args)
        {
            string serviceName = "NetVisorAgent";

            if (!IsAdministrator())
            {
                // Request UAC elevation by restarting itself
                RelaunchAsAdmin(args);
                return;
            }

            if (args.Length == 0)
            {
                ShowMenu(serviceName);
                return;
            }

            string command = args[0].ToLower();
            ExecuteCommand(serviceName, command);
        }

        static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static void RelaunchAsAdmin(string[] args)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.UseShellExecute = true;
            startInfo.WorkingDirectory = Environment.CurrentDirectory;
            startInfo.FileName = Process.GetCurrentProcess().MainModule.FileName;
            startInfo.Arguments = string.Join(" ", args);
            startInfo.Verb = "runas";
            try
            {
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to elevate privileges: " + ex.Message);
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
            }
        }

        static void ShowMenu(string serviceName)
        {
            while (true)
            {
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("=============================================");
                Console.WriteLine("       NetVisor Agent Service Controller     ");
                Console.WriteLine("=============================================");
                Console.ResetColor();

                string status = GetServiceStatus(serviceName);
                Console.Write("Current Service Status: ");
                if (status == "Running")
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                }
                else if (status == "Stopped")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                }
                Console.WriteLine(status);
                Console.ResetColor();
                Console.WriteLine("---------------------------------------------");
                Console.WriteLine("1. Start Service");
                Console.WriteLine("2. Stop Service");
                Console.WriteLine("3. Restart Service");
                Console.WriteLine("4. Install Service");
                Console.WriteLine("5. Uninstall Service");
                Console.WriteLine("6. Refresh Status");
                Console.WriteLine("7. Exit");
                Console.WriteLine("---------------------------------------------");
                Console.Write("Select option (1-7): ");

                string choice = Console.ReadLine();
                switch (choice)
                {
                    case "1":
                        ExecuteCommand(serviceName, "start");
                        break;
                    case "2":
                        ExecuteCommand(serviceName, "stop");
                        break;
                    case "3":
                        ExecuteCommand(serviceName, "restart");
                        break;
                    case "4":
                        InstallService(serviceName);
                        break;
                    case "5":
                        UninstallService(serviceName);
                        break;
                    case "6":
                        break; // Refresh loop
                    case "7":
                        return;
                    default:
                        Console.WriteLine("Invalid option. Press any key to try again...");
                        Console.ReadKey();
                        break;
                }
            }
        }

        static string GetServiceStatus(string serviceName)
        {
            try
            {
                using (ServiceController sc = new ServiceController(serviceName))
                {
                    return sc.Status.ToString();
                }
            }
            catch (Exception)
            {
                return "Not Installed";
            }
        }

        static void InstallService(string serviceName)
        {
            Console.WriteLine("\n[*] Installing NetVisorAgent service...");
            string projectRoot = AppDomain.CurrentDomain.BaseDirectory;
            string pythonExe = Path.Combine(projectRoot, ".venv\\Scripts\\python.exe");
            string serviceScript = Path.Combine(projectRoot, "netvisor_service.py");

            if (!File.Exists(pythonExe))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Error: Python executable not found at: " + pythonExe);
                Console.ResetColor();
                Console.WriteLine("Press any key to return...");
                Console.ReadKey();
                return;
            }

            RunCommand(pythonExe, string.Format("\"{0}\" --startup manual install", serviceScript));
            RunCommand("sc.exe", "failure NetVisorAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000");
            RunCommand("sc.exe", "config NetVisorAgent start= demand");

            // Configure PYTHONPATH in the Service Environment registry key to resolve servicemanager
            try
            {
                Console.WriteLine("[*] Writing service environment variables to registry...");
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Services\NetVisorAgent", true))
                {
                    if (key != null)
                    {
                        string sitePackages = Path.Combine(projectRoot, ".venv\\Lib\\site-packages");
                        string win32Dir = Path.Combine(sitePackages, "win32");
                        string win32Lib = Path.Combine(win32Dir, "lib");
                        string win32Com = Path.Combine(sitePackages, "win32com");
                        string pywinSystem32 = Path.Combine(sitePackages, "pywin32_system32");

                        string pythonHome = "C:\\Python313";
                        try
                        {
                            string pyvenvCfgPath = Path.Combine(projectRoot, ".venv\\pyvenv.cfg");
                            if (File.Exists(pyvenvCfgPath))
                            {
                                foreach (string line in File.ReadLines(pyvenvCfgPath))
                                {
                                    if (line.Trim().StartsWith("home"))
                                    {
                                        string[] parts = line.Split('=');
                                        if (parts.Length > 1)
                                        {
                                            pythonHome = parts[1].Trim();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        catch { }

                        string[] env = new string[] {
                            "PYTHONPATH=" + sitePackages + ";" + win32Dir + ";" + win32Lib + ";" + win32Com,
                            "SystemRoot=C:\\Windows",
                            "PATH=" + pythonHome + ";" + pywinSystem32 + ";C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
                            "NETVISOR_DPI_TRUST_SCOPE=LocalMachine",
                            "NETVISOR_DPI_CAPTURE_MODE=local_browsers"
                        };
                        key.SetValue("Environment", env, Microsoft.Win32.RegistryValueKind.MultiString);
                        Console.WriteLine("[+] Service environment variables configured successfully.");
                    }
                    else
                    {
                        Console.WriteLine("[-] Warning: Service registry key not found.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to configure service environment: " + ex.Message);
            }
            
            Console.WriteLine("\n[+] Installation complete.");
            Console.WriteLine("Press any key to return to menu...");
            Console.ReadKey();
        }

        static void UninstallService(string serviceName)
        {
            Console.WriteLine("\n[*] Uninstalling NetVisorAgent service...");
            string projectRoot = AppDomain.CurrentDomain.BaseDirectory;
            string pythonExe = Path.Combine(projectRoot, ".venv\\Scripts\\python.exe");
            string serviceScript = Path.Combine(projectRoot, "netvisor_service.py");

            if (!File.Exists(pythonExe))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Error: Python executable not found at: " + pythonExe);
                Console.ResetColor();
                Console.WriteLine("Press any key to return...");
                Console.ReadKey();
                return;
            }

            RunCommand(pythonExe, string.Format("\"{0}\" remove", serviceScript));
            
            Console.WriteLine("\n[+] Uninstallation complete.");
            Console.WriteLine("Press any key to return to menu...");
            Console.ReadKey();
        }

        static void RunCommand(string fileName, string arguments)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = fileName;
            startInfo.Arguments = arguments;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.CreateNoWindow = true;

            try
            {
                using (Process process = Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(output)) Console.WriteLine(output.Trim());
                    if (!string.IsNullOrEmpty(error)) Console.WriteLine("Error: " + error.Trim());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Command failed: " + ex.Message);
            }
        }

        static void ExecuteCommand(string serviceName, string command)
        {
            Console.WriteLine(string.Format("\n[*] Executing '{0}' on service '{1}'...", command, serviceName));
            try
            {
                using (ServiceController sc = new ServiceController(serviceName))
                {
                    if (command == "start")
                    {
                        if (sc.Status == ServiceControllerStatus.Running)
                        {
                            Console.WriteLine("[+] Service is already running.");
                        }
                        else
                        {
                            sc.Start();
                            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                            Console.WriteLine("[+] Service started successfully.");
                        }
                    }
                    else if (command == "stop")
                    {
                        if (sc.Status == ServiceControllerStatus.Stopped)
                        {
                            Console.WriteLine("[+] Service is already stopped.");
                        }
                        else
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                            Console.WriteLine("[+] Service stopped successfully.");
                        }
                    }
                    else if (command == "restart")
                    {
                        if (sc.Status == ServiceControllerStatus.Running)
                        {
                            sc.Stop();
                            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        }
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                        Console.WriteLine("[+] Service restarted successfully.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Error: " + ex.Message);
                if (ex.InnerException != null)
                {
                    Console.WriteLine("    Detail: " + ex.InnerException.Message);
                }
                Console.ResetColor();
            }
            Console.WriteLine("\nPress any key to return to menu...");
            Console.ReadKey();
        }
    }
}
