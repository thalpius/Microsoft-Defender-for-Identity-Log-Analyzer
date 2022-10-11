using Microsoft_Defender_for_Identity_Log_Analyzer.Properties;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.Remoting.Contexts;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace Microsoft_Defender_for_Identity_Log_Analyzer
{
    public partial class FormDashboard : Form
    {
        string SensorLog;
        string SensorUpdaterLog;
        string SensorUpdaterErrorsLog;

        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;

        [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
        public static extern bool ReleaseCapture();
        public FormDashboard()
        {
            InitializeComponent();

            MoveSidePanel(btnDashboard);
            richTxtBoxLog.Visible = false;

            lstBoxSensor.Items.Clear();
            lstBoxSensorErrors.Items.Clear();
            lstBoxSensorUpdater.Items.Clear();
            lstBoxSensorUpdaterErrors.Items.Clear();

            pnlSensor.Visible = false;
            pnlSensorErrors.Visible = false;
            pnlSensorUpdater.Visible = false;
            pnlSensorUpdaterErrors.Visible = false;

            btnSensor.Enabled = false;
            btnSensorErrors.Enabled = false;
            btnSensorUpdater.Enabled = false;
            btnSensorUpdaterErrors.Enabled = false;

            CheckLogFiles();
        }

        private void CheckLogFiles()
        {
            MySettings settings = MySettings.Load();

            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var dirName = new DirectoryInfo(latestVersion).Name;
            
            string logSensor = settings.sensor.Replace("VERSION", dirName);
            string logSensorErrors = settings.sensorErrors.Replace("VERSION", dirName);
            string logSensorUpdater = settings.sensorUpdater.Replace("VERSION", dirName);
            string logSensorUpdaterErrors = settings.sensorUpdaterErrors.Replace("VERSION", dirName);

            if (File.Exists(logSensor))
            {
                btnSensor.Enabled = true;
                picBoxSensor.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_512px;
            }
            if (File.Exists(logSensorErrors))
            {
                btnSensorErrors.Enabled = true;
                picBoxSensorErrors.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_errors_512px;
            }
            if (File.Exists(logSensorUpdater))
            {
                btnSensorUpdater.Enabled = true;
                picBoxSensorUpdater.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_updater_512px;
            }
            if (File.Exists(logSensorUpdaterErrors))
            {
                btnSensorUpdaterErrors.Enabled = true;
                picBoxSensorUpdaterErrors.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_updater_errors_512px;
            }
        }

        class MySettings : AppSettings<MySettings>
        {
            public string sensor = "C:\\Program Files\\Azure Advanced Threat Protection Sensor\\VERSION\\Logs\\Microsoft.Tri.Sensor.log";
            public string sensorUpdater = "C:\\Program Files\\Azure Advanced Threat Protection Sensor\\VERSION\\Logs\\Microsoft.Tri.Sensor.Updater.log";
            public string sensorUpdaterErrors = "C:\\Program Files\\Azure Advanced Threat Protection Sensor\\VERSION\\Logs\\Microsoft.Tri.Sensor.Updater-Errors.log";
            public string sensorErrors = "C:\\Program Files\\Azure Advanced Threat Protection Sensor\\VERSION\\Logs\\Microsoft.Tri.Sensor-Errors.log";
        }

        public class AppSettings<T> where T : new()
        {
            private const string DEFAULT_FILENAME = "Microsoft Defender for Identity Log Analyzer.json";
            public void Save(string fileName = DEFAULT_FILENAME)
            {
                File.WriteAllText(fileName, (new JavaScriptSerializer()).Serialize(this));
            }

            public static void Save(T pSettings, string fileName = DEFAULT_FILENAME)
            {
                File.WriteAllText(fileName, (new JavaScriptSerializer()).Serialize(pSettings));
            }

            public static T Load(string fileName = DEFAULT_FILENAME)
            {
                T t = new T();
                if (File.Exists(fileName))
                    t = (new JavaScriptSerializer()).Deserialize<T>(File.ReadAllText(fileName));
                return t;
            }
        }

        private void MoveSidePanel(Control c)
        {
            SidePanel.Height = c.Height;
            SidePanel.Top = c.Top;
        }

        private void lstBoxSensor_MeasureItem(object sender, MeasureItemEventArgs e)
        {
            e.ItemHeight = (int)e.Graphics.MeasureString(lstBoxSensor.Items[e.Index].ToString(), lstBoxSensor.Font, lstBoxSensor.Width).Height;
        }

        private void lstBoxSensor_DrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0)
                return;
            if ((e.State & DrawItemState.Selected) == DrawItemState.Selected)
                e = new DrawItemEventArgs(e.Graphics, e.Font, e.Bounds, e.Index, e.State ^ DrawItemState.Selected, e.ForeColor, Color.SteelBlue);
            e.DrawBackground();
            e.Graphics.DrawString(lstBoxSensor.Items[e.Index].ToString(), e.Font, Brushes.White, e.Bounds, StringFormat.GenericDefault);
            e.DrawFocusRectangle();
        }

        private void lstBoxSensorErrors_MeasureItem(object sender, MeasureItemEventArgs e)
        {
            e.ItemHeight = (int)e.Graphics.MeasureString(lstBoxSensorErrors.Items[e.Index].ToString(), lstBoxSensorErrors.Font, lstBoxSensorErrors.Width).Height;
        }

        private void lstBoxSensorErrors_DrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0)
                return;
            if ((e.State & DrawItemState.Selected) == DrawItemState.Selected)
                e = new DrawItemEventArgs(e.Graphics, e.Font, e.Bounds, e.Index, e.State ^ DrawItemState.Selected, e.ForeColor, Color.SteelBlue);
            e.DrawBackground();
            e.Graphics.DrawString(lstBoxSensorErrors.Items[e.Index].ToString(), e.Font, Brushes.White, e.Bounds, StringFormat.GenericDefault);
            e.DrawFocusRectangle();
        }

        private void lstBoxSensorUpdater_MeasureItem(object sender, MeasureItemEventArgs e)
        {
            e.ItemHeight = (int)e.Graphics.MeasureString(lstBoxSensorUpdater.Items[e.Index].ToString(), lstBoxSensorUpdater.Font, lstBoxSensorUpdater.Width).Height;
        }

        private void lstBoxSensorUpdater_DrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0)
                return;
            if ((e.State & DrawItemState.Selected) == DrawItemState.Selected)
                e = new DrawItemEventArgs(e.Graphics, e.Font, e.Bounds, e.Index, e.State ^ DrawItemState.Selected, e.ForeColor, Color.SteelBlue);
            e.DrawBackground();
            e.Graphics.DrawString(lstBoxSensorUpdater.Items[e.Index].ToString(), e.Font, Brushes.White, e.Bounds, StringFormat.GenericDefault);
            e.DrawFocusRectangle();
        }

        private void lstBoxSensorUpdaterErrors_MeasureItem(object sender, MeasureItemEventArgs e)
        {
            e.ItemHeight = (int)e.Graphics.MeasureString(lstBoxSensorUpdaterErrors.Items[e.Index].ToString(), lstBoxSensorUpdaterErrors.Font, lstBoxSensorUpdaterErrors.Width).Height;
        }

        private void lstBoxSensorUpdaterErrors_DrawItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0)
                return;
            if ((e.State & DrawItemState.Selected) == DrawItemState.Selected)
                e = new DrawItemEventArgs(e.Graphics, e.Font, e.Bounds, e.Index, e.State ^ DrawItemState.Selected, e.ForeColor, Color.SteelBlue);
            e.DrawBackground();
            e.Graphics.DrawString(lstBoxSensorUpdaterErrors.Items[e.Index].ToString(), e.Font, Brushes.White, e.Bounds, StringFormat.GenericDefault);
            e.DrawFocusRectangle();
        }
        private void btnExit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void btnSensor_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "            Sensor", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void btnSensorErrors_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "            Sensor Errors", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void btnSensorUpdater_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "            Sensor Updater", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void btnSensorUpdaterErrors_Paint(object sender, PaintEventArgs e)
        {
            Button btn = (Button)sender;
            btn.Text = string.Empty;
            TextFormatFlags flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
            TextRenderer.DrawText(e.Graphics, "            Sensor Updater Errors", btn.Font, e.ClipRectangle, btn.ForeColor, flags);
        }

        private void btnDashboard_Click(object sender, EventArgs e)
        {
            pbTitle.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.dashboard;
            CheckLogFiles();
            richTxtBoxDashboard.Visible = true;
            richTxtBoxLog.Visible = false;
            pnlSensor.Visible = false;
            pnlDashboard.Visible = true;
            pnlSensorErrors.Visible = false;
            pnlSensorUpdater.Visible = false;
            pnlSensorUpdaterErrors.Visible = false;
            MoveSidePanel(btnDashboard);
        }

        private void btnSensor_Click(object sender, EventArgs e)
        {
            richTxtBoxLog.Visible = true;
            richTxtBoxDashboard.Visible = false;

            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensor = settings.sensor.Replace("VERSION", version);

            richTxtBoxLog.Clear();
            richTxtBoxLog.AppendText("Looking at log:\n" + logSensor + "\n");
            richTxtBoxLog.AppendText("\nVersion Sensor:\n" + version);

            pbTitle.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_512px;

            lstBoxSensor.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawVariable;
            lstBoxSensor.MeasureItem += lstBoxSensor_MeasureItem;
            lstBoxSensor.DrawItem += lstBoxSensor_DrawItem;

            pnlSensor.Visible = true;
            pnlDashboard.Visible = false;
            pnlSensorErrors.Visible = false;
            pnlSensorUpdater.Visible = false;
            pnlSensorUpdaterErrors.Visible = false;

            radioBtnSensorAll.Checked = true;

            MoveSidePanel(btnSensor);
            GetSensorLog();


            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorLog))
            {
                lstBoxSensor.Items.Add(ItemMatch);
            }
            for (int i = 0; i < lstBoxSensor.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensor.Items[i];
                lstBoxSensor.Items[i] = lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1];
                lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1] = tmp;
            }
        }
        private void btnSensorErrors_Click(object sender, EventArgs e)
        {
            richTxtBoxLog.Visible = true;
            richTxtBoxDashboard.Visible = false;

            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensor = settings.sensorErrors.Replace("VERSION", version);

            richTxtBoxLog.Clear();
            richTxtBoxLog.AppendText("Looking at log:\n" + logSensor + "\n");
            richTxtBoxLog.AppendText("\nVersion Sensor:\n" + version);

            pbTitle.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_errors_512px;

            lstBoxSensorErrors.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawVariable;
            lstBoxSensorErrors.MeasureItem += lstBoxSensorErrors_MeasureItem;
            lstBoxSensorErrors.DrawItem += lstBoxSensorErrors_DrawItem;

            pnlSensor.Visible = false;
            pnlDashboard.Visible = false;
            pnlSensorErrors.Visible = true;
            pnlSensorUpdater.Visible = false;
            pnlSensorUpdaterErrors.Visible = false;

            MoveSidePanel(btnSensorErrors);
            GetSensorErrorsLog();

            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorLog))
            {
                lstBoxSensorErrors.Items.Add(ItemMatch);
            }
            for (int i = 0; i < lstBoxSensorErrors.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorErrors.Items[i];
                lstBoxSensorErrors.Items[i] = lstBoxSensorErrors.Items[lstBoxSensorErrors.Items.Count - i - 1];
                lstBoxSensorErrors.Items[lstBoxSensorErrors.Items.Count - i - 1] = tmp;
            }
        }

        private void btnSensorUpdater_Click(object sender, EventArgs e)
        {
            richTxtBoxLog.Visible = true;
            richTxtBoxDashboard.Visible = false;

            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensor = settings.sensorUpdater.Replace("VERSION", version);

            richTxtBoxLog.Clear();
            richTxtBoxLog.AppendText("Looking at log:\n" + logSensor + "\n");
            richTxtBoxLog.AppendText("\nVersion Sensor:\n" + version);

            pbTitle.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_updater_512px;

            lstBoxSensorUpdater.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawVariable;
            lstBoxSensorUpdater.MeasureItem += lstBoxSensorUpdater_MeasureItem;
            lstBoxSensorUpdater.DrawItem += lstBoxSensorUpdater_DrawItem;

            pnlSensor.Visible = false;
            pnlDashboard.Visible = false;
            pnlSensorErrors.Visible = false;
            pnlSensorUpdater.Visible = true;
            pnlSensorUpdaterErrors.Visible = false;

            radioBtnSensorUpdaterAll.Checked = true;

            MoveSidePanel(btnSensorUpdater);
            GetSensorUpdaterLog();

            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorUpdaterLog))
            {
                lstBoxSensorUpdater.Items.Add(ItemMatch);
            }
            for (int i = 0; i < lstBoxSensorUpdater.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorUpdater.Items[i];
                lstBoxSensorUpdater.Items[i] = lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1];
                lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1] = tmp;
            }
        }

        private void btnSensorUpdaterErrors_Click(object sender, EventArgs e)
        {
            richTxtBoxLog.Visible = true;
            richTxtBoxDashboard.Visible = false;

            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensor = settings.sensorUpdaterErrors.Replace("VERSION", version);

            richTxtBoxLog.Clear();
            richTxtBoxLog.AppendText("Looking at log:\n" + logSensor + "\n");
            richTxtBoxLog.AppendText("\nVersion Sensor:\n" + version);

            pbTitle.Image = Microsoft_Defender_for_Identity_Log_Analyzer.Properties.Resources.sensor_updater_errors_512px;

            lstBoxSensorUpdaterErrors.DrawMode = System.Windows.Forms.DrawMode.OwnerDrawVariable;
            lstBoxSensorUpdaterErrors.MeasureItem += lstBoxSensorUpdaterErrors_MeasureItem;
            lstBoxSensorUpdaterErrors.DrawItem += lstBoxSensorUpdaterErrors_DrawItem;

            pnlSensor.Visible = false;
            pnlDashboard.Visible = false;
            pnlSensorErrors.Visible = false;
            pnlSensorUpdater.Visible = false;
            pnlSensorUpdaterErrors.Visible = true;

            MoveSidePanel(btnSensorUpdaterErrors);
            GetSensorUpdaterErrorsLog();

            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorUpdaterErrorsLog))
            {
                lstBoxSensorUpdaterErrors.Items.Add(ItemMatch);
            }
            for (int i = 0; i < lstBoxSensorUpdaterErrors.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorUpdaterErrors.Items[i];
                lstBoxSensorUpdaterErrors.Items[i] = lstBoxSensorUpdaterErrors.Items[lstBoxSensorUpdaterErrors.Items.Count - i - 1];
                lstBoxSensorUpdaterErrors.Items[lstBoxSensorUpdaterErrors.Items.Count - i - 1] = tmp;
            }
        }

        private void pnlTop_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
            }
        }

        public string GetSensorLog()
        {
            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensor = settings.sensor.Replace("VERSION", version);

            const Int32 BufferSize = 128;
            using (var fileStream = File.OpenRead(logSensor))

            using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true, BufferSize))
            {
                return SensorLog = streamReader.ReadToEnd();
            }
        }
        public string GetSensorErrorsLog()
        {
            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensorErrors = settings.sensorErrors.Replace("VERSION", version);

            const Int32 BufferSize = 128;
            using (var fileStream = File.OpenRead(logSensorErrors))

            using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true, BufferSize))
            {
                return SensorLog = streamReader.ReadToEnd();
            }
        }
        public string GetSensorUpdaterLog()
        {
            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensorUpdater = settings.sensorUpdater.Replace("VERSION", version);

            const Int32 BufferSize = 128;
            using (var fileStream = File.OpenRead(logSensorUpdater))

            using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true, BufferSize))
            {
                return SensorUpdaterLog = streamReader.ReadToEnd();
            }
        }
        public string GetSensorUpdaterErrorsLog()
        {
            MySettings settings = MySettings.Load();
            var latestVersion = Directory.GetDirectories(@"C:\Program Files\Azure Advanced Threat Protection Sensor\").OrderByDescending(x => x).FirstOrDefault();
            var version = new DirectoryInfo(latestVersion).Name;
            string logSensorUpdaterErrors = settings.sensorUpdaterErrors.Replace("VERSION", version);

            const Int32 BufferSize = 128;
            using (var fileStream = File.OpenRead(logSensorUpdaterErrors))

            using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true, BufferSize))
            {
                return SensorUpdaterErrorsLog = streamReader.ReadToEnd();
            }
        }

        private void radioBtnSensorUpdaterErrors_Click(object sender, EventArgs e)
        {
            lstBoxSensorUpdater.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorUpdaterLog))
            {
                string GetError = ItemMatch.ToString().Substring(25, 5);
                if (GetError == "Error")
                {
                    lstBoxSensorUpdater.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensorUpdater.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorUpdater.Items[i];
                lstBoxSensorUpdater.Items[i] = lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1];
                lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorUpdaterWarn_Click(object sender, EventArgs e)
        {
            lstBoxSensorUpdater.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorUpdaterLog))
            {
                string GetWarn = ItemMatch.ToString().Substring(25, 4);
                if (GetWarn == "Warn")
                {
                    lstBoxSensorUpdater.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensorUpdater.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorUpdater.Items[i];
                lstBoxSensorUpdater.Items[i] = lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1];
                lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorUpdaterAll_Click(object sender, EventArgs e)
        {
            lstBoxSensorUpdater.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorUpdaterLog))
            {
                lstBoxSensorUpdater.Items.Add(ItemMatch);
            }
            for (int i = 0; i < lstBoxSensorUpdater.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorUpdater.Items[i];
                lstBoxSensorUpdater.Items[i] = lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1];
                lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorUpdaterInfo_Click(object sender, EventArgs e)
        {
            lstBoxSensorUpdater.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorUpdaterLog))
            {
                string GetInfo = ItemMatch.ToString().Substring(25, 4);
                if (GetInfo == "Info")
                {
                    lstBoxSensorUpdater.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensorUpdater.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorUpdater.Items[i];
                lstBoxSensorUpdater.Items[i] = lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1];
                lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorUpdaterDebug_Click(object sender, EventArgs e)
        {
            lstBoxSensorUpdater.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorUpdaterLog))
            {
                string GetInfo = ItemMatch.ToString().Substring(25, 5);
                if (GetInfo == "Debug")
                {
                    lstBoxSensorUpdater.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensorUpdater.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensorUpdater.Items[i];
                lstBoxSensorUpdater.Items[i] = lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1];
                lstBoxSensorUpdater.Items[lstBoxSensorUpdater.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorErrorsErrors_Click(object sender, EventArgs e)
        {
        }
        private void radioBtnSensorAll_Click(object sender, EventArgs e)
        {
            lstBoxSensor.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorLog))
            {
                lstBoxSensor.Items.Add(ItemMatch);
            }
            for (int i = 0; i < lstBoxSensor.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensor.Items[i];
                lstBoxSensor.Items[i] = lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1];
                lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorErrors_Click(object sender, EventArgs e)
        {
            lstBoxSensor.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorLog))
            {
                string GetError = ItemMatch.ToString().Substring(25, 5);
                if (GetError == "Error")
                {
                    lstBoxSensor.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensor.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensor.Items[i];
                lstBoxSensor.Items[i] = lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1];
                lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorWarn_Click(object sender, EventArgs e)
        {
            lstBoxSensor.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorLog))
            {
                string GetError = ItemMatch.ToString().Substring(25, 4);
                if (GetError == "Warn")
                {
                    lstBoxSensor.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensor.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensor.Items[i];
                lstBoxSensor.Items[i] = lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1];
                lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorInfo_Click(object sender, EventArgs e)
        {
            lstBoxSensor.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorLog))
            {
                string GetError = ItemMatch.ToString().Substring(25, 4);
                if (GetError == "info")
                {
                    lstBoxSensor.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensor.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensor.Items[i];
                lstBoxSensor.Items[i] = lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1];
                lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1] = tmp;
            }
        }

        private void radioBtnSensorDebug_Click(object sender, EventArgs e)
        {
            lstBoxSensor.Items.Clear();
            Regex ItemRegex = new Regex(@"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01]) (?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d).\d{4}.*(?:\n(?!\d{4}-).+)*", RegexOptions.Multiline);
            foreach (Match ItemMatch in ItemRegex.Matches(SensorLog))
            {
                string GetError = ItemMatch.ToString().Substring(25, 5);
                if (GetError == "Debug")
                {
                    lstBoxSensor.Items.Add(ItemMatch);
                }
            }
            for (int i = 0; i < lstBoxSensor.Items.Count / 2; i++)
            {
                var tmp = lstBoxSensor.Items[i];
                lstBoxSensor.Items[i] = lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1];
                lstBoxSensor.Items[lstBoxSensor.Items.Count - i - 1] = tmp;
            }
        }

        private void lstBoxSensor_SelectedIndexChanged(object sender, EventArgs e)
        {
            string getitem = lstBoxSensor.GetItemText(lstBoxSensor.SelectedItem);
            if (getitem.Contains("Add an error message"))
            {
                richTxtBoxLog.Clear();
                richTxtBoxLog.AppendText("Add comments to resolve the issue");
            }
        }
    }
}
