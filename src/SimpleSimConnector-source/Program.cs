// Copyright (c) 2026 Alex Nord.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// Commercial use is prohibited without written permission.
using Microsoft.FlightSimulator.SimConnect;
using System;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;

namespace SimpleSimConnector
{
    enum DEFINITIONS
    {
        Telemetry
    }

    enum REQUESTS
    {
        Telemetry
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct Telemetry
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string title;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string atcId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string atcAirline;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string atcFlightNumber;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string atcModel;

        public double latitude;
        public double longitude;
        public double altitude;
        public double groundSpeed;
        public double heading;
        public double onGround;
        public double verticalSpeed;
    }

    class ConnectorSettings
    {
        public string BackendUrl = "http://127.0.0.1:5000/api/telemetry";
        public bool LocalApiEnabled = true;
        public int LocalApiPort = 4789;
        public bool WriteLocalTelemetryFile = true;

        public bool WaitForSim = true;
        public bool AutoExitWithSim = true;
        public int AutoExitDelaySeconds = 10;

        public string[] SimProcessNames = new string[]
        {
            "FlightSimulator2024",
            "FlightSimulator"
        };
    }

    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (args.Length > 0)
            {
                string command = args[0].Trim().ToLowerInvariant();

                try
                {
                    if (command == "--install-autostart")
                    {
                        string changed = MsfsAutostartManager.Install(Application.ExecutablePath);

                        MessageBox.Show(
                            "Autostart installed." +
                            Environment.NewLine + Environment.NewLine +
                            changed,
                            "Simple Sim Connector",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information
                        );

                        return;
                    }

                    if (command == "--uninstall-autostart")
                    {
                        string changed = MsfsAutostartManager.Uninstall();

                        MessageBox.Show(
                            "Autostart removed." +
                            Environment.NewLine + Environment.NewLine +
                            changed,
                            "Simple Sim Connector",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information
                        );

                        return;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        ex.Message,
                        "Simple Sim Connector",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );

                    return;
                }
            }

            Application.Run(new ConnectorForm());
        }
    }

    public class ConnectorForm : Form
    {
        private const int WM_USER_SIMCONNECT = 0x0402;

        private SimConnect simconnect;

        private Label statusLabel;
        private Label latestLabel;
        private Label configLabel;

        private Button installAutostartButton;
        private Button removeAutostartButton;

        private ConnectorSettings settings;

        private TcpListener localApiServer;
        private CancellationTokenSource localApiCancellation;

        private System.Windows.Forms.Timer simWatcherTimer;
        private DateTime? simMissingSinceUtc;
        private bool hasEverConnectedToSim = false;

        private readonly object latestJsonLock = new object();
        private string latestJson;

        private static readonly HttpClient http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(2)
        };

        private readonly string appDataFolder =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SimpleSimConnector"
            );

        private string ExeFolder
        {
            get { return AppDomain.CurrentDomain.BaseDirectory; }
        }

        private string ConfigPath
        {
            get { return Path.Combine(ExeFolder, "connector.ini"); }
        }

        private string LogPath
        {
            get { return Path.Combine(appDataFolder, "connector.log"); }
        }

        private string TelemetryPath
        {
            get { return Path.Combine(appDataFolder, "telemetry.ndjson"); }
        }

        public ConnectorForm()
        {
            Text = "Simple Sim Connector";
            Width = 760;
            Height = 220;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            ShowIcon = true;

            try
            {
                Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch
            {
                // Keep default icon if Windows cannot extract the embedded one.
            }

            statusLabel = new Label
            {
                AutoSize = false,
                Left = 20,
                Top = 18,
                Width = 700,
                Height = 24,
                Text = "Starting..."
            };

            latestLabel = new Label
            {
                AutoSize = false,
                Left = 20,
                Top = 52,
                Width = 700,
                Height = 52,
                Text = "Waiting for telemetry..."
            };

            configLabel = new Label
            {
                AutoSize = false,
                Left = 20,
                Top = 112,
                Width = 700,
                Height = 42,
                Text = ""
            };

            installAutostartButton = new Button
            {
                Left = 20,
                Top = 160,
                Width = 190,
                Height = 30,
                Text = "Install MSFS autostart"
            };

            removeAutostartButton = new Button
            {
                Left = 225,
                Top = 160,
                Width = 190,
                Height = 30,
                Text = "Remove MSFS autostart"
            };

            installAutostartButton.Click += InstallAutostartButton_Click;
            removeAutostartButton.Click += RemoveAutostartButton_Click;

            Controls.Add(statusLabel);
            Controls.Add(latestLabel);
            Controls.Add(configLabel);
            Controls.Add(installAutostartButton);
            Controls.Add(removeAutostartButton);
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            Directory.CreateDirectory(appDataFolder);

            settings = LoadSettings();

            Log("Simple Sim Connector started.");
            Log("Backend URL: " + settings.BackendUrl);
            Log("Local API enabled: " + settings.LocalApiEnabled);
            Log("Local API port: " + settings.LocalApiPort);
            Log("Wait for sim: " + settings.WaitForSim);
            Log("Auto exit with sim: " + settings.AutoExitWithSim);

            configLabel.Text =
                "POST: " + settings.BackendUrl + Environment.NewLine +
                "Local API: " + (settings.LocalApiEnabled
                    ? "http://0.0.0.0:" + settings.LocalApiPort + "/telemetry"
                    : "disabled");

            if (settings.LocalApiEnabled)
            {
                StartLocalApi();
            }

            if (settings.WaitForSim)
            {
                SetStatus("Waiting for Microsoft Flight Simulator 2024...");
                StartSimWatcher();
            }
            else
            {
                SetStatus("Connecting to Microsoft Flight Simulator...");
                ConnectToSim();
            }
        }

        private ConnectorSettings LoadSettings()
        {
            var loaded = new ConnectorSettings();

            if (!File.Exists(ConfigPath))
            {
                string defaultConfig =
                    "# Simple Sim Connector settings" + Environment.NewLine +
                    "backend_url=http://127.0.0.1:5000/api/telemetry" + Environment.NewLine +
                    Environment.NewLine +
                    "local_api_enabled=true" + Environment.NewLine +
                    "local_api_port=4789" + Environment.NewLine +
                    Environment.NewLine +
                    "write_local_telemetry_file=true" + Environment.NewLine +
                    Environment.NewLine +
                    "wait_for_sim=true" + Environment.NewLine +
                    "auto_exit_with_sim=true" + Environment.NewLine +
                    "auto_exit_delay_seconds=10" + Environment.NewLine +
                    "sim_process_names=FlightSimulator2024,FlightSimulator" + Environment.NewLine;

                File.WriteAllText(ConfigPath, defaultConfig);
            }

            foreach (string rawLine in File.ReadAllLines(ConfigPath))
            {
                string line = rawLine.Trim();

                if (line.Length == 0 || line.StartsWith("#"))
                {
                    continue;
                }

                int equalsIndex = line.IndexOf('=');

                if (equalsIndex <= 0)
                {
                    continue;
                }

                string key = line.Substring(0, equalsIndex).Trim().ToLowerInvariant();
                string value = line.Substring(equalsIndex + 1).Trim();

                if (key == "backend_url" && value.Length > 0)
                {
                    loaded.BackendUrl = value;
                }
                else if (key == "local_api_enabled")
                {
                    loaded.LocalApiEnabled = ParseBool(value, loaded.LocalApiEnabled);
                }
                else if (key == "local_api_port")
                {
                    int port;
                    if (int.TryParse(value, out port) && port > 0 && port <= 65535)
                    {
                        loaded.LocalApiPort = port;
                    }
                }
                else if (key == "write_local_telemetry_file")
                {
                    loaded.WriteLocalTelemetryFile = ParseBool(value, loaded.WriteLocalTelemetryFile);
                }
                else if (key == "wait_for_sim")
                {
                    loaded.WaitForSim = ParseBool(value, loaded.WaitForSim);
                }
                else if (key == "auto_exit_with_sim")
                {
                    loaded.AutoExitWithSim = ParseBool(value, loaded.AutoExitWithSim);
                }
                else if (key == "auto_exit_delay_seconds")
                {
                    int seconds;
                    if (int.TryParse(value, out seconds) && seconds >= 0 && seconds <= 300)
                    {
                        loaded.AutoExitDelaySeconds = seconds;
                    }
                }
                else if (key == "sim_process_names")
                {
                    string[] parts = value.Split(',');
                    var names = new System.Collections.Generic.List<string>();

                    foreach (string part in parts)
                    {
                        string cleaned = (part ?? "").Trim();

                        if (cleaned.Length > 0)
                        {
                            names.Add(cleaned);
                        }
                    }

                    if (names.Count > 0)
                    {
                        loaded.SimProcessNames = names.ToArray();
                    }
                }
            }

            return loaded;
        }

        private static bool ParseBool(string value, bool fallback)
        {
            string normalized = (value ?? "").Trim().ToLowerInvariant();

            if (normalized == "true" || normalized == "yes" || normalized == "1" || normalized == "on")
            {
                return true;
            }

            if (normalized == "false" || normalized == "no" || normalized == "0" || normalized == "off")
            {
                return false;
            }

            return fallback;
        }

        private void StartSimWatcher()
        {
            simWatcherTimer = new System.Windows.Forms.Timer();
            simWatcherTimer.Interval = 2000;
            simWatcherTimer.Tick += SimWatcherTick;
            simWatcherTimer.Start();

            Log("Sim watcher started.");
            SimWatcherTick(null, EventArgs.Empty);
        }

        private void SimWatcherTick(object sender, EventArgs e)
        {
            bool simRunning = IsSimulatorRunning();

            if (simRunning)
            {
                simMissingSinceUtc = null;

                if (simconnect == null)
                {
                    SetStatus("MSFS detected. Connecting...");
                    ConnectToSim();
                }

                return;
            }

            if (simconnect != null)
            {
                Log("MSFS process no longer detected. Closing SimConnect.");
                SetStatus("MSFS closed. Disconnecting...");

                CloseSimConnect();
            }

            if (settings.AutoExitWithSim && hasEverConnectedToSim)
            {
                if (simMissingSinceUtc == null)
                {
                    simMissingSinceUtc = DateTime.UtcNow;
                    return;
                }

                double missingSeconds = (DateTime.UtcNow - simMissingSinceUtc.Value).TotalSeconds;

                if (missingSeconds >= settings.AutoExitDelaySeconds)
                {
                    Log("MSFS closed. Auto exiting connector.");
                    Close();
                    return;
                }

                SetStatus("MSFS closed. Exiting in " + Math.Ceiling(settings.AutoExitDelaySeconds - missingSeconds) + "s...");
            }
            else
            {
                SetStatus("Waiting for Microsoft Flight Simulator 2024...");
            }
        }

        private bool IsSimulatorRunning()
        {
            try
            {
                Process[] processes = Process.GetProcesses();

                foreach (Process process in processes)
                {
                    string processName = "";

                    try
                    {
                        processName = process.ProcessName;
                    }
                    catch
                    {
                        continue;
                    }

                    foreach (string configuredName in settings.SimProcessNames)
                    {
                        string wanted = (configuredName ?? "").Trim();

                        if (wanted.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            wanted = wanted.Substring(0, wanted.Length - 4);
                        }

                        if (string.Equals(processName, wanted, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Failed to check simulator process: " + ex.Message);
            }

            return false;
        }

        private void StartLocalApi()
        {
            try
            {
                localApiCancellation = new CancellationTokenSource();
                localApiServer = new TcpListener(IPAddress.Any, settings.LocalApiPort);
                localApiServer.Start();

                Log("Local API listening on 0.0.0.0:" + settings.LocalApiPort);

                Task.Run(() => LocalApiLoop(localApiCancellation.Token));
            }
            catch (Exception ex)
            {
                string message = "Failed to start local API: " + ex.Message;
                Log(message);
                SetStatus(message);
            }
        }

        private async Task LocalApiLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                TcpClient client = null;

                try
                {
                    client = await localApiServer.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleLocalApiClient(client));
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Log("Local API accept error: " + ex.Message);

                    try
                    {
                        if (client != null)
                        {
                            client.Close();
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }

        private void HandleLocalApiClient(TcpClient client)
        {
            using (client)
            {
                try
                {
                    NetworkStream stream = client.GetStream();

                    byte[] buffer = new byte[4096];
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    string firstLine = "";
                    using (StringReader reader = new StringReader(request))
                    {
                        firstLine = reader.ReadLine() ?? "";
                    }

                    string body;
                    string status = "200 OK";
                    string contentType = "application/json";

                    if (firstLine.StartsWith("GET /telemetry ") || firstLine.StartsWith("GET /telemetry?"))
                    {
                        body = GetLatestJsonOrOfflineStatus();
                    }
                    else if (firstLine.StartsWith("GET /health "))
                    {
                        body =
                            "{" +
                                "\"online\":true," +
                                "\"name\":\"simple-sim-connector\"," +
                                "\"source\":\"simconnect-bridge\"" +
                            "}";
                    }
                    else if (firstLine.StartsWith("GET / "))
                    {
                        contentType = "text/plain; charset=utf-8";
                        body =
                            "Simple Sim Connector" + Environment.NewLine +
                            "GET /telemetry" + Environment.NewLine +
                            "GET /health" + Environment.NewLine;
                    }
                    else
                    {
                        status = "404 Not Found";
                        body =
                            "{" +
                                "\"error\":\"not_found\"," +
                                "\"message\":\"Use GET /telemetry or GET /health\"" +
                            "}";
                    }

                    WriteHttpResponse(stream, status, contentType, body);
                }
                catch (Exception ex)
                {
                    Log("Local API client error: " + ex.Message);
                }
            }
        }

        private void WriteHttpResponse(NetworkStream stream, string status, string contentType, string body)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);

            string headers =
                "HTTP/1.1 " + status + "\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + bodyBytes.Length + "\r\n" +
                "Access-Control-Allow-Origin: *\r\n" +
                "Connection: close\r\n" +
                "\r\n";

            byte[] headerBytes = Encoding.ASCII.GetBytes(headers);

            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(bodyBytes, 0, bodyBytes.Length);
        }

        private string GetLatestJsonOrOfflineStatus()
        {
            lock (latestJsonLock)
            {
                if (!string.IsNullOrWhiteSpace(latestJson))
                {
                    return latestJson;
                }
            }

            return
                "{" +
                    "\"online\":true," +
                    "\"connected\":false," +
                    "\"latitude\":null," +
                    "\"longitude\":null," +
                    "\"altitude\":null," +
                    "\"groundspeed\":null," +
                    "\"heading\":null," +
                    "\"callsign\":\"SIMCONNECT\"," +
                    "\"flight_plan\":{" +
                        "\"departure\":null," +
                        "\"arrival\":null," +
                        "\"aircraft_short\":\"UNKNOWN\"" +
                    "}," +
                    "\"source\":\"simconnect-bridge\"," +
                    "\"last_error\":\"No telemetry received yet\"" +
                "}";
        }

        private void ConnectToSim()
        {
            try
            {
                simconnect = new SimConnect(
                    "Simple Sim Connector",
                    Handle,
                    WM_USER_SIMCONNECT,
                    null,
                    0
                );

                simconnect.OnRecvOpen += OnSimConnected;
                simconnect.OnRecvQuit += OnSimQuit;
                simconnect.OnRecvException += OnSimException;
                simconnect.OnRecvSimobjectData += OnTelemetryReceived;

                Log("SimConnect object created.");
                SetStatus("SimConnect object created. Waiting for MSFS...");
            }
            catch (COMException ex)
            {
                simconnect = null;

                string message = "Could not connect to MSFS yet. " + ex.Message;
                Log(message);
                SetStatus("Waiting for SimConnect...");
            }
            catch (Exception ex)
            {
                simconnect = null;

                string message = "Unexpected startup error: " + ex.Message;
                Log(message);
                SetStatus(message);

                SendStatusPayload(false, message);
            }
        }

        private void OnSimConnected(SimConnect sender, SIMCONNECT_RECV_OPEN data)
        {
            hasEverConnectedToSim = true;

            Log("Connected to MSFS.");
            SetStatus("Connected to MSFS. Requesting telemetry...");

            AddStringSimVar("Title");
            AddStringSimVar("ATC ID");
            AddStringSimVar("ATC AIRLINE");
            AddStringSimVar("ATC FLIGHT NUMBER");
            AddStringSimVar("ATC MODEL");

            AddFloatSimVar("Plane Latitude", "degrees");
            AddFloatSimVar("Plane Longitude", "degrees");
            AddFloatSimVar("Plane Altitude", "feet");
            AddFloatSimVar("GROUND VELOCITY", "knots");
            AddFloatSimVar("PLANE HEADING DEGREES TRUE", "degrees");
            AddFloatSimVar("SIM ON GROUND", "bool");
            AddFloatSimVar("VERTICAL SPEED", "feet per minute");

            simconnect.RegisterDataDefineStruct<Telemetry>(DEFINITIONS.Telemetry);

            simconnect.RequestDataOnSimObject(
                REQUESTS.Telemetry,
                DEFINITIONS.Telemetry,
                SimConnect.SIMCONNECT_OBJECT_ID_USER,
                SIMCONNECT_PERIOD.SECOND,
                SIMCONNECT_DATA_REQUEST_FLAG.DEFAULT,
                0,
                0,
                0
            );

            Log("Telemetry request started.");
            SetStatus("Connected. Telemetry request started.");
        }

        private void AddStringSimVar(string name)
        {
            simconnect.AddToDataDefinition(
                DEFINITIONS.Telemetry,
                name,
                null,
                SIMCONNECT_DATATYPE.STRING256,
                0,
                SimConnect.SIMCONNECT_UNUSED
            );
        }

        private void AddFloatSimVar(string name, string unit)
        {
            simconnect.AddToDataDefinition(
                DEFINITIONS.Telemetry,
                name,
                unit,
                SIMCONNECT_DATATYPE.FLOAT64,
                0,
                SimConnect.SIMCONNECT_UNUSED
            );
        }

        private async void OnTelemetryReceived(SimConnect sender, SIMCONNECT_RECV_SIMOBJECT_DATA data)
        {
            if ((REQUESTS)data.dwRequestID != REQUESTS.Telemetry)
            {
                return;
            }

            try
            {
                var telemetry = (Telemetry)data.dwData[0];

                string json = BuildBackendJson(
                    telemetry,
                    connected: true,
                    lastError: null
                );

                lock (latestJsonLock)
                {
                    latestJson = json;
                }

                if (settings.WriteLocalTelemetryFile)
                {
                    AppendTelemetry(json);
                }

                UpdateLatestLabel(telemetry);

                await PostToBackend(json);
            }
            catch (Exception ex)
            {
                string message = "Telemetry handling error: " + ex.Message;
                Log(message);
                SetStatus(message);

                SendStatusPayload(false, message);
            }
        }

        private async Task PostToBackend(string json)
        {
            try
            {
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await http.PostAsync(settings.BackendUrl, content);

                if (!response.IsSuccessStatusCode)
                {
                    Log("Backend returned HTTP " + (int)response.StatusCode + " " + response.ReasonPhrase);
                }
            }
            catch (Exception ex)
            {
                Log("Backend upload failed: " + ex.Message);
            }
        }

        private async void SendStatusPayload(bool connected, string lastError)
        {
            string json =
                "{" +
                    "\"online\":true," +
                    "\"connected\":" + Bool(connected) + "," +
                    "\"latitude\":null," +
                    "\"longitude\":null," +
                    "\"altitude\":null," +
                    "\"groundspeed\":null," +
                    "\"heading\":null," +
                    "\"callsign\":\"SIMCONNECT\"," +
                    "\"flight_plan\":{" +
                        "\"departure\":null," +
                        "\"arrival\":null," +
                        "\"aircraft_short\":\"UNKNOWN\"" +
                    "}," +
                    "\"source\":\"simconnect-bridge\"," +
                    "\"last_error\":" + JsonStringOrNull(lastError) +
                "}";

            lock (latestJsonLock)
            {
                latestJson = json;
            }

            if (settings != null && settings.WriteLocalTelemetryFile)
            {
                AppendTelemetry(json);
            }

            if (settings != null)
            {
                await PostToBackend(json);
            }
        }

        private void OnSimQuit(SimConnect sender, SIMCONNECT_RECV data)
        {
            Log("MSFS quit.");
            SetStatus("MSFS quit. Connector disconnected.");

            SendStatusPayload(false, "MSFS quit");

            CloseSimConnect();
        }

        private void OnSimException(SimConnect sender, SIMCONNECT_RECV_EXCEPTION data)
        {
            string message = "SimConnect exception: " + data.dwException;
            Log(message);
            SetStatus(message);

            SendStatusPayload(false, message);
        }

        protected override void DefWndProc(ref Message m)
        {
            if (m.Msg == WM_USER_SIMCONNECT)
            {
                try
                {
                    simconnect?.ReceiveMessage();
                }
                catch (Exception ex)
                {
                    Log("SimConnect receive error: " + ex.Message);
                    CloseSimConnect();
                }
            }
            else
            {
                base.DefWndProc(ref m);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            Log("Connector closed.");

            if (simWatcherTimer != null)
            {
                simWatcherTimer.Stop();
                simWatcherTimer.Dispose();
                simWatcherTimer = null;
            }

            StopLocalApi();
            CloseSimConnect();

            base.OnClosed(e);
        }

        private void StopLocalApi()
        {
            try
            {
                if (localApiCancellation != null)
                {
                    localApiCancellation.Cancel();
                }

                if (localApiServer != null)
                {
                    localApiServer.Stop();
                }
            }
            catch
            {
            }
        }

        private void CloseSimConnect()
        {
            try
            {
                simconnect?.Dispose();
            }
            catch
            {
            }

            simconnect = null;
        }

        private string BuildBackendJson(Telemetry t, bool connected, string lastError)
        {
            string callsign = BuildCallsign(t);
            string aircraftShort = BuildAircraftShort(t);

            double groundspeed = ZeroNoise(t.groundSpeed, 0.01);
            double heading = NormalizeHeading(t.heading);

            return "{" +
                "\"online\":true," +
                "\"connected\":" + Bool(connected) + "," +
                "\"latitude\":" + Num(t.latitude) + "," +
                "\"longitude\":" + Num(t.longitude) + "," +
                "\"altitude\":" + Num(t.altitude) + "," +
                "\"groundspeed\":" + Num(groundspeed) + "," +
                "\"heading\":" + Num(heading) + "," +
                "\"callsign\":\"" + Escape(callsign) + "\"," +
                "\"flight_plan\":{" +
                    "\"departure\":null," +
                    "\"arrival\":null," +
                    "\"aircraft_short\":\"" + Escape(aircraftShort) + "\"" +
                "}," +
                "\"source\":\"simconnect-bridge\"," +
                "\"last_error\":" + JsonStringOrNull(lastError) +
            "}";
        }

        private string BuildCallsign(Telemetry t)
        {
            string airline = Clean(t.atcAirline);
            string flightNumber = Clean(t.atcFlightNumber);
            string atcId = Clean(t.atcId);

            if (!string.IsNullOrWhiteSpace(airline) && !string.IsNullOrWhiteSpace(flightNumber))
            {
                return airline.Replace(" ", "").ToUpperInvariant() + flightNumber.Replace(" ", "");
            }

            if (!string.IsNullOrWhiteSpace(atcId))
            {
                return atcId.Replace(" ", "").ToUpperInvariant();
            }

            return "SIMCONNECT";
        }

        private string BuildAircraftShort(Telemetry t)
        {
            string model = Clean(t.atcModel);
            string title = Clean(t.title);
            string combined = (model + " " + title).ToUpperInvariant();

            if (!string.IsNullOrWhiteSpace(model))
            {
                string upperModel = model.ToUpperInvariant();

                if (upperModel.Length <= 8)
                {
                    return upperModel;
                }
            }

            if (combined.Contains("A20N")) return "A20N";
            if (combined.Contains("A320")) return "A320";
            if (combined.Contains("A319")) return "A319";
            if (combined.Contains("A321")) return "A321";
            if (combined.Contains("A339") || combined.Contains("A330")) return "A339";
            if (combined.Contains("A359") || combined.Contains("A350")) return "A359";

            if (combined.Contains("B738") || combined.Contains("737-800") || combined.Contains("737")) return "B738";
            if (combined.Contains("B739") || combined.Contains("737-900")) return "B739";
            if (combined.Contains("B789") || combined.Contains("787-9")) return "B789";
            if (combined.Contains("B788") || combined.Contains("787-8")) return "B788";
            if (combined.Contains("B77W") || combined.Contains("777-300")) return "B77W";
            if (combined.Contains("B772") || combined.Contains("777-200")) return "B772";
            if (combined.Contains("B748") || combined.Contains("747-8")) return "B748";
            if (combined.Contains("B744") || combined.Contains("747-400")) return "B744";

            if (combined.Contains("C172") || combined.Contains("172")) return "C172";
            if (combined.Contains("TBM")) return "TBM9";
            if (combined.Contains("CJ4")) return "C25C";
            if (combined.Contains("DA40")) return "DA40";
            if (combined.Contains("DA62")) return "DA62";

            return "UNKNOWN";
        }

        private void AppendTelemetry(string json)
        {
            File.AppendAllText(TelemetryPath, json + Environment.NewLine);
        }

        private void Log(string message)
        {
            Directory.CreateDirectory(appDataFolder);

            File.AppendAllText(
                LogPath,
                DateTime.UtcNow.ToString("o") + " " + message + Environment.NewLine
            );
        }

        private void SetStatus(string message)
        {
            if (statusLabel.InvokeRequired)
            {
                statusLabel.BeginInvoke(new Action(() => statusLabel.Text = message));
            }
            else
            {
                statusLabel.Text = message;
            }
        }

        private void UpdateLatestLabel(Telemetry t)
        {
            string callsign = BuildCallsign(t);
            string aircraftShort = BuildAircraftShort(t);

            string text =
                callsign + " / " + aircraftShort + Environment.NewLine +
                "Lat " + Num(t.latitude) +
                " Lon " + Num(t.longitude) +
                " Alt " + Math.Round(t.altitude).ToString(CultureInfo.InvariantCulture) + " ft" +
                " GS " + Math.Round(ZeroNoise(t.groundSpeed, 0.01)).ToString(CultureInfo.InvariantCulture) + " kt" +
                " HDG " + Math.Round(NormalizeHeading(t.heading)).ToString(CultureInfo.InvariantCulture);

            if (latestLabel.InvokeRequired)
            {
                latestLabel.BeginInvoke(new Action(() => latestLabel.Text = text));
            }
            else
            {
                latestLabel.Text = text;
            }
        }

        private void InstallAutostartButton_Click(object sender, EventArgs e)
        {
            try
            {
                string exePath = Application.ExecutablePath;
                string changedFiles = MsfsAutostartManager.Install(exePath);

                MessageBox.Show(
                    "Simple Sim Connector autostart has been installed." +
                    Environment.NewLine + Environment.NewLine +
                    "Updated:" +
                    Environment.NewLine +
                    changedFiles +
                    Environment.NewLine + Environment.NewLine +
                    "MSFS 2024 should now launch the connector automatically.",
                    "Autostart installed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                Log("Autostart installed: " + changedFiles.Replace(Environment.NewLine, " | "));
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    ex.Message,
                    "Autostart install failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );

                Log("Autostart install failed: " + ex.Message);
            }
        }

        private void RemoveAutostartButton_Click(object sender, EventArgs e)
        {
            try
            {
                string changedFiles = MsfsAutostartManager.Uninstall();

                MessageBox.Show(
                    "Autostart removal complete." +
                    Environment.NewLine + Environment.NewLine +
                    changedFiles,
                    "Autostart removed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                Log("Autostart removed: " + changedFiles.Replace(Environment.NewLine, " | "));
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    ex.Message,
                    "Autostart removal failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );

                Log("Autostart removal failed: " + ex.Message);
            }
        }

        private static string Clean(string value)
        {
            return (value ?? "").Trim();
        }

        private static double ZeroNoise(double value, double threshold)
        {
            return Math.Abs(value) < threshold ? 0 : value;
        }

        private static double NormalizeHeading(double heading)
        {
            heading = heading % 360.0;

            if (heading < 0)
            {
                heading += 360.0;
            }

            return heading;
        }

        private static string Num(double value)
        {
            if (double.IsNaN(value) || double.IsInfinity(value))
            {
                return "null";
            }

            return value.ToString("G17", CultureInfo.InvariantCulture);
        }

        private static string Bool(bool value)
        {
            return value ? "true" : "false";
        }

        private static string JsonStringOrNull(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "null";
            }

            return "\"" + Escape(value) + "\"";
        }

        private static string Escape(string value)
        {
            return (value ?? "")
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
        }
    }

    class MsfsAutostartManager
    {
        private const string AppName = "Simple Sim Connector";

        public static string Install(string exePath)
        {
            string[] baseFolders = GetCandidateBaseFolders();
            int changedCount = 0;
            string result = "";

            foreach (string baseFolder in baseFolders)
            {
                if (!Directory.Exists(baseFolder))
                {
                    continue;
                }

                string exeXmlPath = Path.Combine(baseFolder, "EXE.xml");
                InstallIntoExeXml(exeXmlPath, exePath);
                changedCount++;

                result += exeXmlPath + Environment.NewLine;
            }

            if (changedCount == 0)
            {
                throw new Exception(
                    "Could not find the MSFS 2024 LocalCache folder. Start MSFS 2024 once, then try again."
                );
            }

            return result.Trim();
        }

        public static string Uninstall()
        {
            string[] baseFolders = GetCandidateBaseFolders();
            int changedCount = 0;
            string result = "";

            foreach (string baseFolder in baseFolders)
            {
                if (!Directory.Exists(baseFolder))
                {
                    continue;
                }

                string exeXmlPath = Path.Combine(baseFolder, "EXE.xml");

                if (!File.Exists(exeXmlPath))
                {
                    continue;
                }

                bool removed = RemoveFromExeXml(exeXmlPath);

                if (removed)
                {
                    changedCount++;
                    result += exeXmlPath + Environment.NewLine;
                }
            }

            if (changedCount == 0)
            {
                return "No Simple Sim Connector autostart entry was found.";
            }

            return result.Trim();
        }

        private static string[] GetCandidateBaseFolders()
        {
            return new string[]
            {
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"Packages\Microsoft.Limitless_8wekyb3d8bbwe\LocalCache"
                ),

                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft Flight Simulator 2024"
                )
            };
        }

        private static void InstallIntoExeXml(string exeXmlPath, string exePath)
        {
            string directory = Path.GetDirectoryName(exeXmlPath);

            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            XmlDocument doc = LoadOrCreateExeXml(exeXmlPath);
            XmlElement root = doc.DocumentElement;

            if (File.Exists(exeXmlPath))
            {
                string backupPath = exeXmlPath + ".backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                File.Copy(exeXmlPath, backupPath, true);
            }

            XmlElement addon = FindAddonByName(root, AppName);

            if (addon == null)
            {
                addon = doc.CreateElement("Launch.Addon");
                root.AppendChild(addon);
            }
            else
            {
                addon.RemoveAll();
            }

            AppendElement(doc, addon, "Name", AppName);
            AppendElement(doc, addon, "Disabled", "False");
            AppendElement(doc, addon, "ManualLoad", "False");
            AppendElement(doc, addon, "Path", exePath);
            AppendElement(doc, addon, "CommandLine", "");
            AppendElement(doc, addon, "NewConsole", "False");

            SaveExeXml(doc, exeXmlPath);
        }

        private static bool RemoveFromExeXml(string exeXmlPath)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(exeXmlPath);

            XmlElement root = doc.DocumentElement;
            XmlElement addon = FindAddonByName(root, AppName);

            if (addon == null)
            {
                return false;
            }

            string backupPath = exeXmlPath + ".backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
            File.Copy(exeXmlPath, backupPath, true);

            root.RemoveChild(addon);
            SaveExeXml(doc, exeXmlPath);

            return true;
        }

        private static XmlDocument LoadOrCreateExeXml(string exeXmlPath)
        {
            XmlDocument doc = new XmlDocument();

            if (File.Exists(exeXmlPath))
            {
                doc.Load(exeXmlPath);
                return doc;
            }

            string xml =
                "<?xml version=\"1.0\" encoding=\"Windows-1252\"?>" +
                "<SimBase.Document Type=\"Launch\" version=\"1,0\">" +
                "<Descr>Auto launch external applications on MSFS start</Descr>" +
                "<Filename>EXE.xml</Filename>" +
                "<Disabled>False</Disabled>" +
                "<Launch.ManualLoad>False</Launch.ManualLoad>" +
                "</SimBase.Document>";

            doc.LoadXml(xml);
            return doc;
        }

        private static XmlElement FindAddonByName(XmlElement root, string name)
        {
            foreach (XmlNode node in root.ChildNodes)
            {
                if (node.NodeType != XmlNodeType.Element)
                {
                    continue;
                }

                if (node.Name != "Launch.Addon")
                {
                    continue;
                }

                XmlElement element = (XmlElement)node;
                string addonName = GetChildText(element, "Name");

                if (string.Equals(addonName, name, StringComparison.OrdinalIgnoreCase))
                {
                    return element;
                }
            }

            return null;
        }

        private static string GetChildText(XmlElement parent, string childName)
        {
            foreach (XmlNode node in parent.ChildNodes)
            {
                if (node.NodeType == XmlNodeType.Element && node.Name == childName)
                {
                    return node.InnerText;
                }
            }

            return "";
        }

        private static void AppendElement(XmlDocument doc, XmlElement parent, string name, string value)
        {
            XmlElement element = doc.CreateElement(name);
            element.InnerText = value ?? "";
            parent.AppendChild(element);
        }

        private static void SaveExeXml(XmlDocument doc, string path)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.Encoding = Encoding.GetEncoding("Windows-1252");

            using (XmlWriter writer = XmlWriter.Create(path, settings))
            {
                doc.Save(writer);
            }
        }
    }
}