using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Canvas.Parser;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace PDFILE
{
    #region generated tcp
    /*   // A C# program for Client
       using System;
       using System.Net;
       using System.Net.Sockets;
       using System.Text;

       namespace Client
       {

           class Program
           {

               // Main Method
               static void Main(string[] args)
               {
                   ExecuteClient();
               }

               // ExecuteClient() Method
               static void ExecuteClient()
               {

                   try
                   {

                       // Establish the remote endpoint 
                       // for the socket. This example 
                       // uses port 11111 on the local 
                       // computer.
                       IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                       IPAddress ipAddr = ipHost.AddressList[0];
                       IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 11111);

                       // Creation TCP/IP Socket using 
                       // Socket Class Constructor
                       Socket sender = new Socket(ipAddr.AddressFamily,
                               SocketType.Stream, ProtocolType.Tcp);

                       try
                       {

                           // Connect Socket to the remote 
                           // endpoint using method Connect()
                           sender.Connect(localEndPoint);

                           // We print EndPoint information 
                           // that we are connected
                           Console.WriteLine("Socket connected to -> {0} ",
                                       sender.RemoteEndPoint.ToString());

                           // Creation of message that
                           // we will send to Server
                           byte[] messageSent = Encoding.ASCII.GetBytes("Test Client<EOF>");
                           int byteSent = sender.Send(messageSent);

                           // Data buffer
                           byte[] messageReceived = new byte[1024];

                           // We receive the message using 
                           // the method Receive(). This 
                           // method returns number of bytes
                           // received, that we'll use to 
                           // convert them to string
                           int byteRecv = sender.Receive(messageReceived);
                           Console.WriteLine("Message from Server -> {0}",
                               Encoding.ASCII.GetString(messageReceived,
                                                           0, byteRecv));

                           // Close Socket using 
                           // the method Close()
                           sender.Shutdown(SocketShutdown.Both);
                           sender.Close();
                       }

                       // Manage of Socket's Exceptions
                       catch (ArgumentNullException ane)
                       {

                           Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                       }

                       catch (SocketException se)
                       {

                           Console.WriteLine("SocketException : {0}", se.ToString());
                       }

                       catch (Exception e)
                       {
                           Console.WriteLine("Unexpected exception : {0}", e.ToString());
                       }
                   }

                   catch (Exception e)
                   {

                       Console.WriteLine(e.ToString());
                   }
               }
           }
       }
   */
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
                                Title = line.TrimEnd('-'),
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
                    text = new StringBuilder();
                    TextBox textBox = new TextBox();
                    text.AppendLine($"Title: {vulnerability.Title}");
                    text.AppendLine();

                    if (!string.IsNullOrEmpty(vulnerability.Synopsis))
                    {
                        text.AppendLine($"Synopsis: \n{vulnerability.Synopsis}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Description))
                    {
                        text.AppendLine($"Description: \n{vulnerability.Description}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.See_Also))
                    {
                        text.AppendLine($"See Also: \n{vulnerability.See_Also}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Solution))
                    {
                        text.AppendLine($"Solution: \n{vulnerability.Solution}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Risk_Factor))
                    {
                        text.AppendLine($"Risk Factor: \n{vulnerability.Risk_Factor}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_Base_Score))
                    {
                        text.AppendLine($"CVSS Base Score: \n{vulnerability.CVSS_Base_Score}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Base_Score))
                    {
                        text.AppendLine($"CVSS V3.0 Base Score: \n{vulnerability.CVSS_V30_Base_Score}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_Temporal_Score))
                    {
                        text.AppendLine($"CVSS Temporal Score: \n{vulnerability.CVSS_Temporal_Score}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.CVSS_V30_Temporal_Score))
                    {
                        text.AppendLine($"CVSS V3.0 Temporal Score: \n{vulnerability.CVSS_V30_Temporal_Score}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Plugin_Information))
                    {
                        text.AppendLine($"Plugin Information: \n{vulnerability.Plugin_Information}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.Plugin_Output))
                    {
                        text.AppendLine($"Plugin Output: \n{vulnerability.Plugin_Output}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.References))
                    {
                        text.AppendLine($"References: \n{vulnerability.References}");
                        text.AppendLine();
                    }

                    if (!string.IsNullOrEmpty(vulnerability.STIG_Severity))
                    {
                        text.AppendLine($"STIG Severity: \n{vulnerability.STIG_Severity}");
                        text.AppendLine();
                    }

                    textBox.Text = text.ToString();
                    lblLyonatán.Children.Add(textBox);
                }


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
    }
}