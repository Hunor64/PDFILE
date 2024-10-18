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


        private void ReadPdf(string filePath)
        {
            try
            {
                using (PdfReader pdfReader = new PdfReader(filePath))
                using (PdfDocument pdfDocument = new PdfDocument(pdfReader))
                {
                    StringBuilder text = new StringBuilder();
                    Vulnerability currentVulnerability = null;

                    for (int i = 1; i <= pdfDocument.GetNumberOfPages(); i++)
                    {
                        string pageText = PdfTextExtractor.GetTextFromPage(pdfDocument.GetPage(i));
                        string[] lines = pageText.Split('\n');

                        string currentContent = "";
                        string[] currentLines = [];
                        string[] allClassElements = []

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
                                    Title = line
                                };
                            }
                            else if ()
                            {
                                
                            }
                        }
                    }

                    if (currentVulnerability != null)
                    {
                        vulnerabilities.Add(currentVulnerability);
                    }

                    foreach (Vulnerability vulnerability in vulnerabilities)
                    {
                        text.AppendLine($"Title: {vulnerability.Title}");
                        text.AppendLine($"Description: {vulnerability.Description}");
                        text.AppendLine();
                    }

                    lblLyonatán.Content = text.ToString();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error reading PDF: {ex.Message}");
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

                if (line.Substring(5, 3) == " - ")
                {
                    return true;
                }
            }

            return false;
        }
    }
}