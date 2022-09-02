using Ban_Server_Library;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

const string FirewallName = "***REMOTE_BAN***";
const string RemoteCategory = "Security";
const string MSSQLCategory = "Application";

bool useRemote = false;
bool useMssql = false;

int failedCount = 1;

List<string> whiteList;

try
{
    string fileName = "jsconfig.json";
    string jsonString = File.ReadAllText($".\\{fileName}");
    Settings settings = JsonSerializer.Deserialize<Settings>(jsonString)!;

    useRemote = settings.REMOTE;
    useMssql = settings.MSSQL;

    failedCount = settings.FailedCount;

    whiteList = settings.WhiteLists;
}
catch (Exception ex)
{
    ErrorLog.WriteError($"setting error---{ex.Message}");
    return;
}

Dictionary<string, int> ipTable = new Dictionary<string, int>();

try
{
    EventLog[] ele = Array.FindAll(EventLog.GetEventLogs(Environment.MachineName.Trim()), x => ((x.Log.Trim() == RemoteCategory && useRemote) || (x.Log.Trim() == MSSQLCategory && useMssql)));
    Regex rx = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");

    foreach (EventLog log in ele)
    {
        IEnumerable<EventLogEntry> Iele = log.Entries.Cast<EventLogEntry>().Where(x => x.InstanceId == 4625 || x.InstanceId == 3221243928 || x.InstanceId == 3221243308);

        foreach (EventLogEntry entry in Iele)
        {
            MatchCollection matches = rx.Matches(entry.Message);

            if (matches.Count > 0)
            {
                if (ipTable.ContainsKey(matches[0].Value))
                    ipTable[matches[0].Value] += 1;
                else
                    ipTable.Add(matches[0].Value, 1);
            }
        }
    }

    StringBuilder IPs = new StringBuilder(string.Empty);
    IEnumerable<KeyValuePair<string, int>> items = ipTable.Where(x => x.Value >= failedCount);

    foreach (KeyValuePair<string, int> item in items)
        IPs.Append(item.Key).Append(',');

    if (!IPs.ToString().Trim().Equals(string.Empty))
    {
        string existsIps = FirewallAPI.GetBlockIP(FirewallName).Trim();
        IPs.Append(existsIps).Append(',');

        foreach (string whiteip in whiteList)
        {
            IPs.Replace(whiteip + ",", string.Empty);
            IPs.Replace(whiteip + "/255.255.255.255,", string.Empty);
        }

        char t = IPs.ToString()[IPs.Length - 1];
        if (t == ',')
            IPs.Remove(IPs.Length - 1, 1);

        FirewallAPI.RemoveInboundRule(FirewallName);
        FirewallAPI.AddInboudRuleIPBlock(FirewallName, FirewallAPI.Protocol.Any, IPs.ToString());
    }
}
catch (Exception ex)
{
    ErrorLog.WriteError($"run error---{ex.Message}");
}