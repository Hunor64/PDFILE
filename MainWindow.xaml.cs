using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Canvas.Parser;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PDFILE
{
    public partial class MainWindow : Window
    {
        List<Vulnerability> vulnerabilities = new List<Vulnerability>();

        public MainWindow()
        {
            InitializeComponent();
            ReadPdf("SampleNetworkVulnerabilityScanReport.pdf");
            ExecuteClientAsync(); // Start the TCP client asynchronously after reading the PDF
        }

        string pdfContent;

        #region TCP connection
        private async void ExecuteClientAsync()
        {
            try
            {
                // Establish the remote endpoint for the socket.
                IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddr = ipHost.AddressList[0];
                IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 11111);

                // Creation of TCP/IP Socket using Socket Class Constructor
                using (Socket sender = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                {
                    try
                    {
                        // Connect Socket to the remote endpoint
                        await Task.Run(() => sender.Connect(localEndPoint));

                        // Create a single string to send all vulnerabilities
                        StringBuilder allVulnerabilitiesText = new StringBuilder();
                        foreach (Vulnerability vulnerability in vulnerabilities)
                        {
                            allVulnerabilitiesText.AppendLine($"Title: {vulnerability.Title}");
                            allVulnerabilitiesText.AppendLine();

                            if (!string.IsNullOrEmpty(vulnerability.Synopsis))
                            {
                                allVulnerabilitiesText.AppendLine($"Synopsis: \n{vulnerability.Synopsis}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.Description))
                            {
                                allVulnerabilitiesText.AppendLine($"Description: \n{vulnerability.Description}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.See_Also))
                            {
                                allVulnerabilitiesText.AppendLine($"See Also: \n{vulnerability.See_Also}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.Solution))
                            {
                                allVulnerabilitiesText.AppendLine($"Solution: \n{vulnerability.Solution}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.Risk_Factor))
                            {
                                allVulnerabilitiesText.AppendLine($"Risk Factor: \n{vulnerability.Risk_Factor}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.CVSS_Base_Score))
                            {
                                allVulnerabilitiesText.AppendLine($"CVSS Base Score: \n{vulnerability.CVSS_Base_Score}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Base_Score))
                            {
                                allVulnerabilitiesText.AppendLine($"CVSS V3.0 Base Score: \n{vulnerability.CVSS_V30_Base_Score}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.CVSS_Temporal_Score))
                            {
                                allVulnerabilitiesText.AppendLine($"CVSS Temporal Score: \n{vulnerability.CVSS_Temporal_Score}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Temporal_Score))
                            {
                                allVulnerabilitiesText.AppendLine($"CVSS V3.0 Temporal Score: \n{vulnerability.CVSS_V30_Temporal_Score}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.Plugin_Information))
                            {
                                allVulnerabilitiesText.AppendLine($"Plugin Information: \n{vulnerability.Plugin_Information}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.Plugin_Output))
                            {
                                allVulnerabilitiesText.AppendLine($"Plugin Output: \n{vulnerability.Plugin_Output}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.References))
                            {
                                allVulnerabilitiesText.AppendLine($"References: \n{vulnerability.References}");
                                allVulnerabilitiesText.AppendLine();
                            }

                            if (!string.IsNullOrEmpty(vulnerability.STIG_Severity))
                            {
                                allVulnerabilitiesText.AppendLine($"STIG Severity: \n{vulnerability.STIG_Severity}");
                                allVulnerabilitiesText.AppendLine();
                            }
                        }

                        byte[] pdfBytes = Encoding.UTF8.GetBytes(allVulnerabilitiesText.ToString() + "<EOF>"); // Append <EOF> to indicate end of message

                        sender.Send(pdfBytes);

                        // Data buffer to receive the message

                        byte[] messageReceived = new byte[1024000];

                        // Receive the message

                        int byteRecv = sender.Receive(messageReceived);

                        string receivedMessage = Encoding.ASCII.GetString(messageReceived, 0, byteRecv);

                        // Update the UI with the received message

                        AddMessageToStackPanel(receivedMessage);

                        // Close Socket
                        sender.Shutdown(SocketShutdown.Both);
                    }
                    catch (Exception ex)
                    {
                        AddMessageToStackPanel($"Exception: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                AddMessageToStackPanel($"General Exception: {ex.Message}");
            }
        }

        private void AddMessageToStackPanel(string message)
        {
            // Create a TextBlock for the received message
            TextBlock messageTextBlock = new TextBlock
            {
                Text = message,
                Margin = new Thickness(0, 5, 0, 5)
            };

            // Add the TextBlock to the StackPanel (Negro)
            Negro.Children.Add(messageTextBlock);
        }
        #endregion

        #region PDF reader
        public void ReadPdf(string filePath)
        {
            using (PdfReader pdfReader = new PdfReader(filePath))
            using (PdfDocument pdfDocument = new PdfDocument(pdfReader))
            {
                StringBuilder text = new StringBuilder();
                vulnerabilities.Clear(); // Clear previous vulnerabilities to avoid memory accumulation
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
                                Title = line.TrimEnd('-'),
                            };
                        }
                        else if (IsCategory(line.Trim()))
                        {
                            if (currentVulnerability != null && currentCategory != "")
                            {
                                ModifyVulnerability(currentVulnerability, currentCategory, currentLines);
                                currentCategory = line.Trim();
                                currentLines.Clear(); // Clear previous lines to avoid memory accumulation
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

                // Create a new StringBuilder for text output
                StringBuilder outputText = new StringBuilder();

                foreach (Vulnerability vulnerability in vulnerabilities)
                {
                    outputText.Clear(); // Clear previous text before appending new content
                    outputText.AppendLine($"Title: {vulnerability.Title}");
                    outputText.AppendLine();

                    if (!string.IsNullOrEmpty(vulnerability.Synopsis))
                    {
                        outputText.AppendLine($"Synopsis: \n{vulnerability.Synopsis}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Description))
                    {
                        outputText.AppendLine($"Description: \n{vulnerability.Description}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.See_Also))
                    {
                        outputText.AppendLine($"See Also: \n{vulnerability.See_Also}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Solution))
                    {
                        outputText.AppendLine($"Solution: \n{vulnerability.Solution}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Risk_Factor))
                    {
                        outputText.AppendLine($"Risk Factor: \n{vulnerability.Risk_Factor}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_Base_Score))
                    {
                        outputText.AppendLine($"CVSS Base Score: \n{vulnerability.CVSS_Base_Score}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Base_Score))
                    {
                        outputText.AppendLine($"CVSS V3.0 Base Score: \n{vulnerability.CVSS_V30_Base_Score}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_Temporal_Score))
                    {
                        outputText.AppendLine($"CVSS Temporal Score: \n{vulnerability.CVSS_Temporal_Score}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Temporal_Score))
                    {
                        outputText.AppendLine($"CVSS V3.0 Temporal Score: \n{vulnerability.CVSS_V30_Temporal_Score}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Plugin_Information))
                    {
                        outputText.AppendLine($"Plugin Information: \n{vulnerability.Plugin_Information}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Plugin_Output))
                    {
                        outputText.AppendLine($"Plugin Output: \n{vulnerability.Plugin_Output}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.References))
                    {
                        outputText.AppendLine($"References: \n{vulnerability.References}");
                        outputText.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.STIG_Severity))
                    {
                        outputText.AppendLine($"STIG Severity: \n{vulnerability.STIG_Severity}");
                        outputText.AppendLine();
                    }

                    TextBox textBox = new TextBox();
                    textBox.Text = outputText.ToString();
                    pdfContent = textBox.Text; // Assign the text to pdfContent
                    lblLyonatán.Children.Add(textBox);
                }
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
            else if (line.Substring(6, 3) == " - ")
            {
                return true;
            }
            return false;
        }

        public bool IsCategory(string sor)
        {
            string[] validCategories = {
                    "Synopsis", "Description", "See Also", "Solution",
                    "Risk Factor", "CVSS Base Score", "CVSS v3.0 Base Score",
                    "CVSS Temporal Score", "CVSS v3.0 Temporal Score",
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

                case "CVSS v3.0 Base Score":
                    vulnerability.CVSS_V30_Base_Score = string.Join("\n", lines);
                    break;

                case "CVSS Temporal Score":
                    vulnerability.CVSS_Temporal_Score = string.Join("\n", lines);
                    break;

                case "CVSS v3.0 Temporal Score":
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
        #endregion
    }
}