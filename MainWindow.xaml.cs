﻿using System.Text;
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

    class TcpServerExample
    {
        static void Main(string[] args)
        {
            // Define the server's IP address and port
            string serverIp = "127.0.0.1"; // Change this to the server's IP address if needed
            int port = 8080; // Same port as the client

            // Create a TCP listener
            TcpListener server = new TcpListener(IPAddress.Parse(serverIp), port);
            server.Start();
            Console.WriteLine("Server started, waiting for a connection...");

            try
            {
                // Accept incoming client connection
                using (TcpClient client = server.AcceptTcpClient())
                {
                    Console.WriteLine("Client connected.");

                    // Get the network stream
                    NetworkStream stream = client.GetStream();

                    // Buffer for reading data
                    byte[] buffer = new byte[256];
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    string receivedMessage = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    Console.WriteLine("Received from client: {0}", receivedMessage);

                    // Optionally, process the message here (e.g., log it)

                    // Create a response (you can customize this as needed)
                    string responseMessage = "Message received!";
                    byte[] responseData = Encoding.ASCII.GetBytes(responseMessage);

                    // Send response back to the client
                    stream.Write(responseData, 0, responseData.Length);
                    Console.WriteLine("Sent back to client: {0}", responseMessage);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.Message);
            }
            finally
            {
                server.Stop();
                Console.WriteLine("Server stopped.");
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


        private void ReadPdf(string filePath)
        {
            try
            {
                using (PdfReader pdfReader = new PdfReader(filePath))
                using (PdfDocument pdfDocument = new PdfDocument(pdfReader))
                {
                    StringBuilder text = new StringBuilder();
                    List<Vulnerability> vulnerabilities = new List<Vulnerability>();
                    Vulnerability currentVulnerability = null;

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
                                    Description = ""
                                };
                            }
                            else if (IsCategory(line.Trim()))
                            {
                                if (currentVulnerability != null && !string.IsNullOrEmpty(currentVulnerability.Description))
                                {
                                    vulnerabilities.Add(currentVulnerability);
                                }

                                currentVulnerability = new Vulnerability
                                {
                                    Title = line,
                                    Description = ""
                                };
                            }
                            else if (currentVulnerability != null)
                            {
                                if (!string.IsNullOrEmpty(currentVulnerability.Description))
                                {
                                    currentVulnerability.Description += "\n";
                                }
                                currentVulnerability.Description += line.Trim();
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
            catch (Exception ex)
            {
                MessageBox.Show($"Error reading PDF: {ex.Message}");
            }
        }

        public bool IsHeader(string line)
        {
            return line.Length >= 8 && line.StartsWith("#####") && line.Substring(5, 3) == " - ";
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
        //public Vulnerability Modify(Vulnerability vulnerability,string category, string[] lines)
        //{
        //    switch (category)
        //    {
        //        case "Synopsis":
        //        case "Description":
        //        case "See Also":
        //        case "Solution":
        //        case "Risk Factor":
        //        case "CVSS Base Score":
        //        case "CVSS V3.0 Base Score":
        //        case "CVSS Temporal Score":
        //        case "CVSS V3.0 Temporal Score":
        //        case "Plugin Information":
        //        case "Plugin Output":
        //        case "References":
        //        case "STIG Severity":
        //            return true;
        //        default:
        //            return false;
        //    }


        //    return vulnerability;
        //}
    }
}