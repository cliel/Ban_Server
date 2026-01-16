using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ban_Server_Library
{
    public class Settings
    {
        public int FailedCount { get; set; }
        public List<string> WhiteLists { get; set; } = new();
    }
}