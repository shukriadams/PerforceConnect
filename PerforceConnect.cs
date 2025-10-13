using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

/// <summary>
/// Single file, zero-dependency Perforce helper library. Drop into your project and do the Perforce things.
/// </summary>
namespace Madscience_PerforceConnect
{
    /// <summary>
    /// 
    /// </summary>
    public class PerforceConnect
    {
        #region FIELDS

        /// <summary>
        /// Username to connect to perforce with.
        /// </summary>
        private readonly string _p4User;

        /// <summary>
        /// Plain-text password of user to connect to perforce with.
        /// </summary>
        private readonly string _p4ticket;
        
        /// <summary>
        /// Address / URL of your perforce server. Normally looks like "ssl:p4.example.com:1666".
        /// </summary>
        private readonly string _p4Port;

        /// <summary>
        /// Trust signature for perforce. Use "p4 trust -l" to figure yours out, and keep updated as necessary.
        /// </summary>
        private readonly string _p4Fingerprint;

        private Dictionary<string, string> _tickets = new Dictionary<string, string>();

        #endregion

        #region CTORS

        /// <summary>
        /// 
        /// </summary>
        /// <param name="p4User"></param>
        /// <param name="ticket"></param>
        /// <param name="p4Port"></param>
        /// <param name="p4Fingerprint"></param>
        public PerforceConnect(string p4User, string ticket, string p4Port, string p4Fingerprint, bool ticketIsPassword) 
        {
            _p4User = p4User;
            _p4ticket = ticket;   
            _p4Fingerprint = p4Fingerprint;
            _p4Port = p4Port;

            // if ticket is already a proper ticket, store it in ticket collection, all subsequent ticket usage will bypass
            // auth and use this directly
            if (!ticketIsPassword)
                _tickets.Add(p4User+p4Port, ticket);
        }

        #endregion

        #region METHODS

        /// <summary>
        /// Runs a shell command synchronously, returns concatenated stdout, stderr and error code.
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        private static ShellResult Run(string command)
        {
            Process cmd = new Process();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                cmd.StartInfo.FileName = "sh";
                cmd.StartInfo.Arguments = $"-c \"{command}\"";
            }
            else
            {
                cmd.StartInfo.FileName = "cmd.exe";
                cmd.StartInfo.Arguments = $"/k {command}";
            }

            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.RedirectStandardError = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;

            List<string> stdOut = new List<string>();
            List<string> stdErr = new List<string>();
            int timeout = 50000;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                using (AutoResetEvent outputWaitHandle = new AutoResetEvent(false))
                using (AutoResetEvent errorWaitHandle = new AutoResetEvent(false))
                {
                    cmd.OutputDataReceived += (sender, e) =>
                    {
                        try
                        {
                            if (e.Data == null)
                                outputWaitHandle.Set();
                            else
                                stdOut.Add(e.Data);
                        }
                        catch (Exception ex)
                        {
                            stdErr.Add(e.ToString());
                        }
                    };

                    cmd.ErrorDataReceived += (sender, e) =>
                    {
                        try
                        {
                            if (e.Data == null)
                                errorWaitHandle.Set();
                            else
                                stdErr.Add(e.Data);
                        }
                        catch (Exception ex)
                        {
                            stdErr.Add(ex.ToString());
                        }
                    };

                    cmd.Start();
                    cmd.BeginOutputReadLine();
                    cmd.BeginErrorReadLine();

                    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || (cmd.WaitForExit(timeout) && outputWaitHandle.WaitOne(timeout) && errorWaitHandle.WaitOne(timeout)))
                        return new ShellResult
                        {
                            StdOut = stdOut,
                            StdErr = stdErr,
                            ExitCode = cmd.ExitCode
                        };
                    else
                        throw new Exception($"Timed out on command : {command} after {timeout} ms");
                }
            }
            else
            {
                cmd.Start();
                cmd.StandardInput.Flush();
                cmd.StandardInput.Close();


                while (!cmd.StandardOutput.EndOfStream)
                {
                    string line = cmd.StandardOutput.ReadLine();
                    stdOut.Add(line);
                }

                while (!cmd.StandardError.EndOfStream)
                {
                    string line = cmd.StandardError.ReadLine();
                    stdErr.Add(line);
                }

                return new ShellResult
                {
                    StdOut = stdOut,
                    StdErr = stdErr,
                    ExitCode = cmd.ExitCode
                };
            }
        }


        /// <summary>
        /// Converts windows line endings to unix
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static string StandardizeLineEndings(string input)
        {
            return Regex.Replace(input, @"\r\n", "\n");
        }


        /// <summary>
        /// Compact and safe regex find - tries to find a string in another string, if found, returns result, else returns empty string.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="regexPattern"></param>
        /// <returns></returns>
        private static string Find(string text, string regexPattern, RegexOptions options = RegexOptions.None, string defaultValue = "")
        {
            MatchCollection matches = new Regex(regexPattern, options).Matches(text);
            if (!matches.Any())
                return defaultValue;

            return string.Join(string.Empty, matches.Select(m => m.Groups[1].Value));
        }


        /// <summary>
        /// gets a p4 ticket for user. Tickets are cached in memory. This is a cludge fix for now, because ticket is generated once in memory, then we 
        /// assume it always works. If ticket is revoked after server start, we have to restart it to recreate ticket. tickets should be checked 
        /// on-the-fly, but that needs to be done higher up than this method.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="host"></param>
        private string GetTicket(string username, string password, string host, string trustFingerPrint)
        {
            string key = username + host;
            if (_tickets.ContainsKey(key))
                return _tickets[key];

            string command = $"echo {password}|p4 -p {host} -u {username} login && p4 -p {host} tickets";
            if (!string.IsNullOrEmpty(trustFingerPrint))
                command = $"p4 -p {host} trust -i {trustFingerPrint.ToUpper()} && p4 -p {host} trust -f -y && {command}";

            var result = Run(command);
            // perforce cannot establish trust + get ticket at same time because it is stupid.
            if (string.Join("\n", result.StdOut).ToLower().Contains("already established"))
                result = Run(command);

            if (result.ExitCode != 0 || result.StdErr.Any())
                throw new Exception($"Failed to login, got code {result.ExitCode} - {string.Join("\n", result.StdErr)}");

            foreach (string outline in result.StdOut)
                if (outline.Contains($"({username})"))
                {
                    string ticket = outline.Split(" ")[2];
                    _tickets.Add(key, ticket);
                    return ticket;
                }

            throw new Exception($"Failed to get ticket - {string.Join("\n", result.StdErr)} {string.Join("\n", result.StdOut)}. If trust is already established, ignore this error. ");
        }


        /// <summary>
        /// Returns true if "p4" works at the local command line. Requires that you install and configure p4 properly.
        /// </summary>
        /// <returns></returns>
        public bool IsP4InstalledLocally()
        {
            Console.Write("WBTB : Verifying p4 client available locally, you can safely ignore any authentication errors immediately following this line.");
            ShellResult result = Run($"p4 set");
            string stdErr = string.Join("", result.StdErr);
            if (stdErr.Contains("is not recognized as an internal or external command") || stdErr.Contains("'p4' not found"))
                return false;

            return true;
        }


        /// <summary>
        /// Gets detailed contents of a change using the P4 describe command. Returns null if revision does not exist.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="host"></param>
        /// <param name="revision"></param>
        /// <returns></returns>
        public string GetRawDescribe(string revision)
        {
            string ticket = GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);
            string command = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} describe -s {revision}";

            ShellResult result = Run(command);

            if (result.ExitCode != 0 || result.StdErr.Any())
            {
                string stderr = string.Join("\r\n", result.StdErr);
                if (stderr.Contains("no such changelist"))
                    return null;

                // ignore text encoding issues
                // todo : find a better way to fix this
                if (stderr.Contains("No Translation for parameter 'data'"))
                    throw new Exception("Invalid revision encoding"); // do not change exception message, we're hardcoded referring to further up

                if (stderr.Contains("'p4 trust' command"))
                    Console.WriteLine("Note that you can force p4 trust by adding Trust: true to your source server's Config: block");

                throw new Exception($"P4 command {command} exited with code {result.ExitCode}, revision {revision}, error : {stderr}");
            }

            return string.Join("\n", result.StdOut);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="clientname"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public string GetRawClient(string clientname)
        {
            string ticket = GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);
            string command = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} client -o {clientname}";

            ShellResult result = Run(command);

            if (result.ExitCode != 0 || result.StdErr.Any())
            {
                string stderr = string.Join("\r\n", result.StdErr);

                // todo : how to detect invalid clientname ??

                if (stderr.Contains("'p4 trust' command"))
                    Console.WriteLine("Note that you can force p4 trust by adding Trust: true to your source server's Config: block");

                throw new Exception($"P4 command {command} exited with code {result.ExitCode}, error : {stderr}");
            }

            return string.Join("\n", result.StdOut);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="rawClient"></param>
        /// <returns></returns>
        public Client ParseClient(string rawClient)
        {
            /*
            
            Expected rawClient is :

                Client: myclient
                Access: 2020/04/12 10:18:31
                Owner:  myuser
                Host:   mypcname
                Description:
                        Created by myuser etc etc.
                Root:   D:\path\to\my\workspace
                Options:        noallwrite noclobber nocompress unlocked nomodtime normdir
                SubmitOptions:  submitunchanged
                LineEnd:        local
                Stream: //mydepot/mystream
                View:
                        //mydepot/mystream/mydir/%%1 //myclient/%%1
                        //mydepot/mystream/some/path/... //myclient/path/...
                        //mydepot/mystream/some/other/path/... //myclient/path2/...


            Note:
                first line in View remaps the files in mydir to the root directtory of the workspace
                
             */

            // convert all windows linebreaks to unix 
            rawClient = StandardizeLineEndings(rawClient);

            string[] commentStrip = rawClient.Split("\n");
            rawClient = string.Join("\n", commentStrip.Where(r => !r.StartsWith("#")));
            string name = Find(rawClient, @"Client:\s*(.*?)\n", RegexOptions.IgnoreCase);
            string root = Find(rawClient, @"Root:\s*(.*?)\n", RegexOptions.IgnoreCase);
            string viewItemsRaw = Find(rawClient, @"View:\n([\s\S]*.*?)", RegexOptions.Multiline);
            string[] viewItems = viewItemsRaw.Split("\n");
            IList<ClientView> views = new List<ClientView>();

            for (int i = 0; i < viewItems.Length; i++)
            {
                viewItems[i] = viewItems[i].Trim();
                // there will be empty string after trim, ignore these
                if (viewItems[i].Length == 0)
                    continue;

                views.Add(new ClientView
                {
                    // everything before the space is the remote part of the view, everything after the local remap
                    Remote = Find(viewItems[i], @"(.*?)\s"),
                    Local = Find(viewItems[i], @"\s(.*?)$")
                });
            }

            return new Client
            {
                Root = root,
                Name = name,
                Views = views
            };
        }

        /// <summary>
        /// Returns a list of client names a given user has on a given host.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="host"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public IEnumerable<string> GetClientsForUserAndHost(string user, string host) 
        {
            string ticket = GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);
            string command = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} clients -u {user}";

            ShellResult result = Run(command);

            if (result.ExitCode != 0 || result.StdErr.Any())
            {
                string stderr = string.Join("\r\n", result.StdErr);

                if (stderr.Contains("'p4 trust' command"))
                    Console.WriteLine("Note that you can force p4 trust by adding Trust: true to your source server's Config: block");

                throw new Exception($"P4 command {command} exited with code {result.ExitCode}, error : {stderr}");
            }

            List<string> clients = new List<string>();

            foreach (string line in result.StdOut) 
            {
                Console.WriteLine($"::{line}");
                string clientName = Find(line, @"^Client (.*) \d", RegexOptions.IgnoreCase);
                if (string.IsNullOrEmpty(clientName))
                    continue;

                string subCommand = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} client -o {clientName}";
                ShellResult subResult = Run(subCommand);

                if (result.ExitCode != 0 || result.StdErr.Any())
                {
                    string stderr = string.Join("\r\n", subResult.StdErr);
                    throw new Exception($"P4 command {subCommand} exited with code {result.ExitCode}, error : {stderr}");
                }
        
                foreach(string line2 in subResult.StdOut)
                    if (Find(line2, $"Host:\\W+(.*)", RegexOptions.IgnoreCase) == host) 
                    {
                        clients.Add(clientName);
                        break;
                    }
            }

            return clients;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="host"></param>
        public void VerifyCredentials()
        {
            GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="rawDescribe"></param>
        /// <param name="parseDifferences"></param>
        /// <returns></returns>
        public Change ParseDescribe(string rawDescribe, bool parseDifferences = true)
        {
            // convert all windows linebreaks to unix 
            rawDescribe = StandardizeLineEndings(rawDescribe);

            // use revision lookup to determine if describe is valid - on Windows systems we don't get an error code when doing an invalid
            // lookup, so we need to "probe" the text this way.
            string revision = Find(rawDescribe, @"change ([\d]+) ", RegexOptions.IgnoreCase);
            if (string.IsNullOrEmpty(revision))
                throw new Exception($"P4 describe failed, got invalid content \"{rawDescribe}\".");

            // s modifier selects across multiple lines
            string descriptionRaw = Find(rawDescribe, @"\n\n(.*?)\n\nAffected files ...", RegexOptions.IgnoreCase & RegexOptions.Multiline).Trim();
            IList<ChangeFile> files = new List<ChangeFile>();

            // affected files is large block listing all files which have been affected by revision
            string affectedFilesRaw = string.Empty;
            if (rawDescribe.Contains("Differences ..."))
            {
                affectedFilesRaw = Find(rawDescribe, @"\n\nAffected files ...\n\n(.*)?\n\nDifferences ...", RegexOptions.IgnoreCase);
            }
            else
            {
                int position = rawDescribe.IndexOf("\n\nAffected files ...");
                if (position > 0)
                    // use substring because regex is too shit to ignore linebreaks
                    affectedFilesRaw = rawDescribe.Substring(position, rawDescribe.Length - position);  // Find(rawDescribe, @"\n\nAffected files ...\n\n(.*)?", RegexOptions.IgnoreCase);
            }


            // multiline grab
            string differencesRaw = Find(rawDescribe, @"\n\nDifferences ...\n\n(.*)", RegexOptions.IgnoreCase);

            affectedFilesRaw = affectedFilesRaw == null ? string.Empty : affectedFilesRaw;
            IEnumerable<string> affectedFiles = affectedFilesRaw.Split("\n");

            IEnumerable<string> differences = differencesRaw.Split(@"\n==== ");

            foreach (string affectedFile in affectedFiles)
            {
                Match match = new Regex(@"... (.*)#[\d]+ (delete|add|edit|integrate)$", RegexOptions.IgnoreCase).Match(affectedFile);
                if (!match.Success || match.Groups.Count < 2)
                    continue;

                ChangeFile item = new ChangeFile
                {
                    File = match.Groups[1].Value,
                    Change = match.Groups[2].Value
                };

                // try to get difference
                if (parseDifferences)
                    foreach (string difference in differences)
                    {
                        string file = Find(difference, @" (.*?)#[\d]+ .+ ====");
                        if (file == item.File)
                            item.Differences = Find(difference, @"#.+====(.*)")
                                .Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
                    }

                files.Add(item);
            }

            IEnumerable<string> description = descriptionRaw.Split("\n", StringSplitOptions.RemoveEmptyEntries);
            description = description.Select(line => line.Trim());

            // parse out and strip optional *pending* string from date sequence. Could probably be done entirely 
            // in regex but that would require effort.
            string rawDate = Find(rawDescribe, @"change [\d]+ by.+? on (.*?)\n", RegexOptions.IgnoreCase);
            rawDate = rawDate.Replace("*pending*", string.Empty);

            return new Change
            {
                Revision = revision,
                ChangeFilesCount = affectedFiles.Count(),
                Workspace = Find(rawDescribe, @"change [\d]+ by.+@(.*?) on ", RegexOptions.IgnoreCase),
                Date = DateTime.Parse(rawDate),
                User = Find(rawDescribe, @"change [\d]+ by (.*?)@", RegexOptions.IgnoreCase),
                Files = files,
                Description = string.Join(" ", description)
            };
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="host"></param>
        /// <param name="filePath"></param>
        /// <param name="revision"></param>
        /// <returns></returns>
        public IEnumerable<string> GetRawAnnotate(string filePath, string revision = null)
        {
            string ticket = GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);

            string revisionSwitch = string.Empty;
            if (!string.IsNullOrEmpty(revision))
                revisionSwitch = $"@{revision}";

            string command = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} annotate -c {filePath}{revisionSwitch}";
            ShellResult result = Run(command);
            if (result.ExitCode != 0)
                throw new Exception($"P4 command {command} exited with code {result.ExitCode} : {result.StdErr}");

            return result.StdOut;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="raw"></param>
        /// <returns></returns>
        private AnnotateChange? TryParseAnnotateType(string raw)
        {
            try
            {
                return (AnnotateChange)Enum.Parse(typeof(AnnotateChange), raw);
            }
            catch
            {
                return null;
            }
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="lines"></param>
        /// <returns></returns>
        public Annotate ParseAnnotate(IEnumerable<string> lines)
        {
            lines = lines.Where(line => !string.IsNullOrEmpty(line));
            string revision = string.Empty;
            string file = string.Empty;
            AnnotateChange? change = null;
            IList<AnnotateLine> annotateLines = new List<AnnotateLine>();

            // parse out first line, this contains description
            if (lines.Count() > 0)
            {
                file = Find(lines.ElementAt(0), @"^(.*?) -");
                revision = Find(lines.ElementAt(0), @" change (.*?) ");
                change = TryParseAnnotateType(Find(lines.ElementAt(0), @" - (.*?) change "));
            }

            if (lines.Count() > 1)
                // start start 2nd item in array
                for (int i = 1; i < lines.Count(); i++)
                {
                    // normally first text on annotate line is "revisionnumber: ", but there can be other console noise at end, we 
                    // search for confirmed rev nr, and if not found, we ignore line
                    string rawRevision = Find(lines.ElementAt(i), @"^(.*?): ");
                    if (string.IsNullOrEmpty(rawRevision))
                        continue;

                    AnnotateLine line = new AnnotateLine();
                    annotateLines.Add(line);
                    line.Revision = rawRevision;
                    line.Text = Find(lines.ElementAt(i), @":(.*)$");
                    line.LineNumber = i;
                }

            return new Annotate
            {
                File = file,
                Change = change,
                Revision = revision,
                Lines = annotateLines
            };
        }


        /// <summary>
        /// Gets raw p4 lookup of revisions from now back in time.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="host"></param>
        /// <param name="max"></param>
        /// <param name="path"></param>
        /// <returns></returns>
        public IEnumerable<string> GetRawChanges(bool shelves, int max = 0, string path = "//...")
        {
            string ticket = GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);
            string shelfModifier = shelves ? "-s shelved" : string.Empty;
            string maxModifier = max > 0 ? $"-m {max}" : string.Empty;
            string command = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} changes {maxModifier} {shelfModifier} -l {path}";

            ShellResult result = Run(command);
            if (result.ExitCode != 0)
                throw new Exception($"P4 command {command} exited with code {result.ExitCode} : {string.Join("\n", result.StdErr)}");

            return result.StdOut;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="changeNumber"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public IEnumerable<string> GetRawChange(string changeNumber)
        {
            string ticket = GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);

            string command = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} change -o {changeNumber}";

            ShellResult result = Run(command);
            if (result.ExitCode != 0)
                throw new Exception($"P4 command {command} exited with code {result.ExitCode} : {string.Join("\n", result.StdErr)}");

            return result.StdOut;
        }


        /// <summary>
        /// Gets raw p4 lookup of revisions between two change nrs.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="host"></param>
        /// <param name="trustFingerPrint"></param>
        /// <param name="startRevision"></param>
        /// <param name="endRevision"></param>
        /// <param name="path"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public IEnumerable<string> GetRawChangesBetween(string startRevision, string endRevision, string path = "//...")
        {
            string ticket = GetTicket(_p4User, _p4ticket, _p4Port, _p4Fingerprint);
            IList<string> revisions = new List<string>();

            string command = $"p4 -u {_p4User} -p {_p4Port} -P {ticket} changes {path}@{startRevision},@{endRevision} ";
            ShellResult result = Run(command);
            // bizarrely, p4 changes returns both stdout and stderr for changes
            if (result.ExitCode != 0 || (result.StdErr.Any() && !result.StdOut.Any()))
                throw new Exception($"P4 command {command} exited with code {result.ExitCode} : {string.Join("\n", result.StdErr)}");

            if (result.StdOut.Any())
                foreach (string line in result.StdOut)
                {
                    if (!line.StartsWith("Change "))
                        continue;

                    string revisionFound = Find(line, @"change (\d*?) ", RegexOptions.IgnoreCase);

                    // don't include tail-end revision
                    revisions.Add(revisionFound);
                }

            // remove the range revisions, we want only those between
            revisions.Remove(startRevision.ToString());
            revisions.Remove(endRevision.ToString());

            return revisions;
        }


        /// <summary>
        /// Parses out change without file details. 
        /// </summary>
        /// <param name="rawChanges"></param>
        /// <returns></returns>
        public IEnumerable<Change> ParseChanges(IEnumerable<string> rawChanges)
        {
            List<Change> changes = new List<Change>();
            Change currentChange = new Change();

            foreach (string changeLine in rawChanges)
            {
                if (changeLine.StartsWith("Change "))
                {
                    currentChange = new Change();
                    changes.Add(currentChange);

                    currentChange.Revision = Find(changeLine, @"change ([\d]+) ", RegexOptions.IgnoreCase);
                    currentChange.User = Find(changeLine, @"change [\d]+ on .+ by (.*)@", RegexOptions.IgnoreCase);
                    currentChange.Workspace = Find(changeLine, @"change [\d]+ on .+ by .+@(.*)", RegexOptions.IgnoreCase);
                    currentChange.Date = DateTime.Parse(Find(changeLine, @"change [\d]+ on (.*?) by ", RegexOptions.IgnoreCase));
                }
                else
                {
                    // remove tab chars, replace them with spaces as they server as spaces in formatted p4 messages.
                    // trim to remove those spaces when added add beginning of commit message, where the \t is effectively used as a newline
                    currentChange.Description += changeLine.Replace(@"\t", " ").Trim();
                }
            }

            return changes;
        }

        /// <summary>
        /// Tries to find a trust string associated with a given ip + port. Returns null if none found.
        /// </summary>
        /// <param name="ip"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static string TryResolveTrust(string ip, int port) 
        {
            string command = $"p4 trust -l";
            ShellResult result = Run(command);
            if (result.ExitCode != 0 || (result.StdErr.Any()))
                throw new Exception($"P4 command {command} exited with code {result.ExitCode} : {string.Join("\n", result.StdErr)}");

            foreach (string line in result.StdOut) 
            {
                if (line.StartsWith($"{ip}:{port}"))
                    return Find(line, ".* (.*)");
            }

            return null;
        }


        /// <summary>
        /// Tries to resolve an IP from standard p4port setting (ssl:address:port). Returns tokenized result.
        /// Note that P4port may already be in IP format.
        /// </summary>
        /// <param name="p4Port"></param>
        /// <returns></returns>
        public static P4PortResolveResult ResolveP4PortToIP(string p4Port) 
        {
            Match match = new Regex("(?:ssl.)?(.+):(\\d+)", RegexOptions.IgnoreCase).Match(p4Port);
            if (match.Length == 0)
                return new P4PortResolveResult {  Error = $"p4port string {p4Port} appears to be invalid." };

            string host = match.Groups[1].Value;
            string ip = null;
            int port = int.Parse(match. Groups[2].Value);
            bool hostIsIP = new Regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$", RegexOptions.IgnoreCase).Match(host).Length > 0;

            // if not ip, resolve hostname to ip
            if (!hostIsIP) 
            {
                ShellResult result = Run($"nslookup {host}");
                if (result.ExitCode != 0)
                    throw new Exception($"nslookup on host {host} exited with code {result.ExitCode} : {string.Join("\n", result.StdErr)}");

                for (int i = 0; i < result.StdOut.Count(); i++) 
                {
                    string line = result.StdOut.ElementAt(i);
                    if (Find(line, $"Name:(.*)", RegexOptions.IgnoreCase).Trim().ToLower() == host.ToLower() && i < result.StdOut.Count() -1) 
                    {
                        ip = Find(result.StdOut.ElementAt(i + 1), "Address:(.*)", RegexOptions.IgnoreCase).Trim();
                    }
                }
            }

            return new P4PortResolveResult { 
                Host = host, 
                IP = ip,
                Port = port 
            };
        }

        /// <summary>
        /// Tries to resolve a p4 ticket from current p4 context, for the given user+host+port combination. Returns null if none found.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="host"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static string TryResolveTicket(string user, string ip, int port) 
        {
            ShellResult result = Run($"p4 tickets");
            if (result.ExitCode != 0)
                throw new Exception($"p4 ticket exited with code {result.ExitCode}, {string.Join("\n", result.StdErr)}");

            foreach (string ticketLine in result.StdOut) 
            {
                Match lookup = new Regex("(.*):(\\d+) \\((.*)\\) (.*)").Match(ticketLine);
                if (lookup.Groups.Count >= 4) 
                {
                    string lookup_host = lookup.Groups[1].Value;
                    string lookup_port = lookup.Groups[2].Value;
                    string lookup_user = lookup.Groups[3].Value;
                    if (lookup_host == ip && lookup_port == port.ToString() && lookup_user == user)
                        return lookup.Groups[4].Value;
                }
            }

            return null;
        }

        #endregion
    }

    public class P4PortResolveResult 
    {
        public string Host { get; set; } = string.Empty;

        public int Port { get; set; }

        public string IP { get; set; }

        public string Error { get; set; }
    }

    /// <summary>
    /// 
    /// </summary>
    public enum AnnotateChange
    {
        add,
        edit,
        delete
    }

    public class ClientView
    {
        public string Remote { get; set; }
        public string Local { get; set; }
    }

    public class Client
    {
        public string Name { get; set; }
        public string Root { get; set; }
        public IEnumerable<ClientView> Views { get; set; }

        public Client()
        {
            this.Views = new ClientView[] { };
        }
    }

    /// <summary>
    /// 
    /// </summary>
    public class Annotate
    {
        /// <summary>
        /// Revision annotation was taken at
        /// </summary>
        public string Revision { get; set; }

        public string File { get; set; }

        public AnnotateChange? Change { get; set; }

        public IList<AnnotateLine> Lines { get; set; }

        public Annotate()
        {
            Lines = new List<AnnotateLine>();
            File = string.Empty;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    public class AnnotateLine
    {
        /// <summary>
        /// Revision that changed this line
        /// </summary>
        public string Revision { get; set; }

        public string Text { get; set; }

        /// <summary>
        /// Line number
        /// </summary>
        public int LineNumber { get; set; }

        public AnnotateLine()
        {
            Text = string.Empty;
        }
    }


    /// <summary>
    /// A change aka revision aka commit, in Perforce parlance.
    /// </summary>
    public class Change
    {
        public string Revision { get; set; }
        public string Workspace { get; set; }
        public DateTime Date { get; set; }
        public string User { get; set; }
        public string Description { get; set; }
        public int ChangeFilesCount { get; set; }
        public IEnumerable<ChangeFile> Files { get; set; }

        public Change()
        {
            Workspace = string.Empty;
            User = string.Empty;
            Description = string.Empty;
            Files = new List<ChangeFile>();
        }

        public override string ToString()
        {
            return @$"Revision {this.Revision},
                Description {Description}, 
                Date {Date}, 
                Workspace {Workspace}, 
                User {User}";
        }
    }


    /// <summary>
    /// A file in a Changeset.
    /// </summary>
    public class ChangeFile
    {
        public string File { get; set; }

        /// <summary>
        /// Can be (delete|add|edit|integrate)
        /// </summary>
        public string Change { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public IEnumerable<string> Differences { get; set; }

        public Annotate Annotate { get; set; }

        public ChangeFile()
        {
            File = string.Empty;
            Change = string.Empty;
            Differences = new string[] { };
        }
    }


    /// <summary>
    /// Result of shell command.
    /// </summary>
    internal class ShellResult
    {
        /// <summary>
        /// Normally 0 when command succeeds and something else when it fails, but Perforce can return warnings or even info as errors.
        /// </summary>
        public int ExitCode { get; set; }

        /// <summary>
        /// Standard output, per line.
        /// </summary>
        public IEnumerable<string> StdOut { get; set; }

        /// <summary>
        /// Error output, per line.
        /// </summary>
        public IEnumerable<string> StdErr { get; set; }

        public ShellResult()
        {
            this.StdOut = new string[] { };
            this.StdErr = new string[] { };
        }
    }
    
    /// <summary>
    /// Type of shell to connect to perforce with.
    /// </summary>
    internal enum ShellType
    {
        Sh,     // typically used on Linux, but can be installed and used on Windows
        Cmd     // default Windows DOS shell
    }

}
