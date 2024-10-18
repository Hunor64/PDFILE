using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Canvas.Parser;

namespace PDFILE
{
    #region generated tcp
    /* using System;
     using System.Net;
     using System.Net.Sockets;
     using System.Text;

     class TcpClientExample
     {
         static void Main(string[] args)
         {
             // Define the server address and port
             string serverIp = "127.0.0.1"; // Change this to the server's IP address
             int port = 8080; // Change this to the server's port

             try
             {
                 // Create a TCP client
                 using (TcpClient client = new TcpClient())
                 {
                     // Connect to the server
                     client.Connect(IPAddress.Parse(serverIp), port);
                     Console.WriteLine("Connected to the server.");

                     // Get the network stream
                     NetworkStream stream = client.GetStream();

                     // Send a message to the server
                     string message = "Hello, Server!";
                     byte[] data = Encoding.ASCII.GetBytes(message);
                     stream.Write(data, 0, data.Length);
                     Console.WriteLine("Sent: {0}", message);

                     // Receive a response from the server
                     byte[] buffer = new byte[256];
                     int bytesRead = stream.Read(buffer, 0, buffer.Length);
                     string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                     Console.WriteLine("Received: {0}", response);
                 }
             }
             catch (Exception ex)
             {
                 Console.WriteLine("Error: {0}", ex.Message);
             }
         }
     }*/
    #endregion

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        List<Vulnerability> vulnerabilities = new List<Vulnerability>();
        public MainWindow()
        {
            InitializeComponent();
            ReadPdf("SampleNetworkVulnerabilityScanReport.pdf");
        }


        public void ReadPdf(string filePath)
        {

            using (PdfReader pdfReader = new PdfReader(filePath))
            using (PdfDocument pdfDocument = new PdfDocument(pdfReader))
            {
                StringBuilder text = new StringBuilder();
                List<Vulnerability> vulnerabilities = new List<Vulnerability>();
                Vulnerability currentVulnerability = null;
                    List<string> currentLines = new();
                    string currentCategory = "";

                for (int i = 1; i <= pdfDocument.GetNumberOfPages(); i++)
                {
                    string pageText = PdfTextExtractor.GetTextFromPage(pdfDocument.GetPage(i));
                    string[] lines = pageText.Split('\n');

                    foreach (string line in lines)
                    {
                        if (IsHeader(line))
                        {
                            if (currentVulnerability != null)
                            {
                                vulnerabilities.Add(currentVulnerability);
                            }

                            currentVulnerability = new Vulnerability
                            {
                                Title = line,
                            };
                        }
                        else if (IsCategory(line.Trim()))
                        {
                            if (currentVulnerability != null && currentCategory != "")
                            {
                                ModifyVulnerability(currentVulnerability, currentCategory, currentLines);
                                currentCategory = line.Trim();
                                currentLines = new();
                            }
                            else
                            {
                                currentCategory = line.Trim();
                            }
                        }

                        else if (currentVulnerability != null)
                        {
                            currentLines.Add(line.Trim());
                        }
                    }
                }

                if (currentVulnerability != null)
                {
                    vulnerabilities.Add(currentVulnerability);
                }

                #region Write all lines
                foreach (Vulnerability vulnerability in vulnerabilities)
                {
                    text.AppendLine($"Title: {vulnerability.Title}");

                    if (!string.IsNullOrEmpty(vulnerability.Synopsis))
                    {
                        text.AppendLine($"Synopsis: {vulnerability.Synopsis}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Description))
                    {
                        text.AppendLine($"Description: {vulnerability.Description}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.See_Also))
                    {
                        text.AppendLine($"See Also: {vulnerability.See_Also}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Solution))
                    {
                        text.AppendLine($"Solution: {vulnerability.Solution}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Risk_Factor))
                    {
                        text.AppendLine($"Risk Factor: {vulnerability.Risk_Factor}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_Base_Score))
                    {
                        text.AppendLine($"CVSS Base Score: {vulnerability.CVSS_Base_Score}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Base_Score))
                    {
                        text.AppendLine($"CVSS V3.0 Base Score: {vulnerability.CVSS_V30_Base_Score}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_Temporal_Score))
                    {
                        text.AppendLine($"CVSS Temporal Score: {vulnerability.CVSS_Temporal_Score}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Temporal_Score))
                    {
                        text.AppendLine($"CVSS V3.0 Temporal Score: {vulnerability.CVSS_V30_Temporal_Score}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Plugin_Information))
                    {
                        text.AppendLine($"Plugin Information: {vulnerability.Plugin_Information}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Plugin_Output))
                    {
                        text.AppendLine($"Plugin Output: {vulnerability.Plugin_Output}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.References))
                    {
                        text.AppendLine($"References: {vulnerability.References}");
                    }

                    if (!string.IsNullOrEmpty(vulnerability.STIG_Severity))
                    {
                        text.AppendLine($"STIG Severity: {vulnerability.STIG_Severity}");
                    }

                    text.AppendLine();
                }

                lblLyonatán.Content = text.ToString();
                #endregion

            }
        }

        public bool IsHeader(string line)
        {
            if (line.Length >= 8)
            {
                for (int i = 0; i < 5; i++)
                {
                    if (!char.IsDigit(line[i]))
                    {
                        return false;
                    }
                }
            }
            else
            {
                return false;
            }

            if (line.Substring(5, 3) == " - ")
            {
                return true;
            }
            return false;
        }

        public bool IsCategory(string sor)
        {
            string[] validCategories = {
                "Synopsis", "Description", "See Also", "Solution",
                "Risk Factor", "CVSS Base Score", "CVSS V3.0 Base Score",
                "CVSS Temporal Score", "CVSS V3.0 Temporal Score",
                "Plugin Information", "Plugin Output", "References",
                "STIG Severity"
            };

            return validCategories.Contains(sor);

        }

        private Vulnerability ModifyVulnerability(Vulnerability currentVulnerability, string category, List<string> lines)
        {
            Vulnerability vulnerability = currentVulnerability;
            switch (category)
            {
                case "Synopsis":
                    vulnerability.Synopsis = string.Join("\n", lines);
                    break;
                case "Description":
                    vulnerability.Description = string.Join("\n", lines);
                    break;
                case "See Also":
                    vulnerability.See_Also = string.Join("\n", lines);
                    break;
                case "Solution":
                    vulnerability.Solution = string.Join("\n", lines);
                    break;
                case "Risk Factor":
                    vulnerability.Risk_Factor = string.Join("\n", lines);
                    break;

                case "CVSS Base Score":
                    vulnerability.CVSS_Base_Score = string.Join("\n", lines);
                    break;

                case "CVSS V3.0 Base Score":
                    vulnerability.CVSS_V30_Base_Score = string.Join("\n", lines);
                    break;

                case "CVSS Temporal Score":
                    vulnerability.CVSS_Temporal_Score = string.Join("\n", lines);
                    break;

                case "CVSS V3.0 Temporal Score":
                    vulnerability.CVSS_V30_Temporal_Score = string.Join("\n", lines);
                    break;

                case "Plugin Information":
                    vulnerability.Plugin_Information = string.Join("\n", lines);
                    break;

                case "Plugin Output":
                    vulnerability.Plugin_Output = string.Join("\n", lines);
                    break;
                case "References":
                    vulnerability.References = string.Join("\n", lines);
                    break;

                case "STIG Severity":
                    vulnerability.STIG_Severity = string.Join("\n", lines);
                    break;

                default:
                    break;

            }

            return vulnerability;
        }
    }
}