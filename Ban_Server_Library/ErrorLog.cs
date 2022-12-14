using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ban_Server_Library
{
    public class ErrorLog
    {
        private static string filePath = string.Empty;

        static ErrorLog()
        {
            if (string.IsNullOrEmpty(filePath))
                filePath = System.IO.Directory.GetCurrentDirectory();
        }

        public static void WriteError(string ex)
        {
            WriteError(new Exception(ex));
        }

        public static void WriteError(Exception ex)
        {
            string fileName = DateTime.Now.ToString("yyyyMMdd") + ".log";
            string fullPath = Path.Combine(filePath, fileName.Substring(0, 4) + "\\" + fileName.Substring(4, 2));

            if (!Directory.Exists(fullPath))
                Directory.CreateDirectory(fullPath);

            StringBuilder message = new StringBuilder(0);
            message.Append("Error DateTime : ").Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")).Append(Environment.NewLine);
            message.Append("Error Message").Append(Environment.NewLine);
            message.Append("----------------------------------------------------------------------").Append(Environment.NewLine);
            message.Append(ex.ToString()).Append(Environment.NewLine);
            message.Append("--created by cliel.com------------------------------------------------").Append(Environment.NewLine).Append(Environment.NewLine);

            StreamWriter sw = null;

            try
            {
                sw = File.AppendText(Path.Combine(fullPath, fileName));
                sw.WriteLine(message.ToString());
            }
            catch
            {
                //
            }
            finally
            {
                if (sw != null)
                    sw.Close();
            }
        }
    }
}