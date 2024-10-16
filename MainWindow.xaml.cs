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
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
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
                    for (int i = 1; i <= pdfDocument.GetNumberOfPages(); i++)
                    {
                        string pageText = PdfTextExtractor.GetTextFromPage(pdfDocument.GetPage(i));
                        string[] lines = pageText.Split('\n');

                        foreach (string line in lines)
                        {
                            if (IsHeader(line))
                            {
                            }
                            else
                            {
                                text.Append(line + "\n");
                            }
                        }
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
            //line.Contains(" - ")
            /*  if (System.Text.RegularExpressions.Regex.IsMatch(line, @"^\d{5} - "))
              {
                  return true;
              }*/

            if (line.Length >= 8)
            {
                // Check if the first 5 characters are digits
                for (int i = 0; i < 5; i++)
                {
                    if (!char.IsDigit(line[i]))
                    {
                        return false; // Return false if any of the first 5 characters is not a digit
                    }
                }

                // Check if the next part is " - "
                if (line.Substring(5, 3) == " - ")
                {
                    return true; // Return true if the format matches
                }
            }

            return false;
        }
    }
}