using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security.Principal;
using System.Xml;
using DotNetEnv;

namespace EventAgentUnified
{
  internal class Program
  {
    /* ── Sysmon ETW 설정 ─────────────────────────────────────────────── */
    private const string SysmonProvider = "Microsoft-Windows-Sysmon";
    private const ulong SysmonKeywords = ulong.MaxValue;
    private const TraceEventLevel SysmonLevel = TraceEventLevel.Informational;
    private const string SessionName = "EventAgent";

    // 제외할 Sysmon 이벤트 ID
    private static readonly int[] SysmonSkipIds = { };

    /* ── Security(EventLog) 설정 ─────────────────────────────────────── */
    private static readonly int[] SecurityEventIds =
        { 4624, 4625, 4648, 4672, 4663, 4697, 4698, 4699 };

    /* ── OpenTelemetry ───────────────────────────────────────────────── */
    private static readonly TracerProvider? Otel;

    private static readonly ActivitySource Src = new("event.agent");

    private static readonly ConcurrentDictionary<int, Activity> RootsByPid = new();
    private static readonly ConcurrentDictionary<int, int> LastParent = new();

    private static Activity? GetOrCreateRoot(int pid, int ppid = 0)
    {
      if (pid == 0) return null;

      if (!RootsByPid.TryGetValue(pid, out var root))
      {
        ActivityContext parentCtx = default;
        if (ppid != 0 && RootsByPid.TryGetValue(ppid, out var parentRoot) && parentRoot != null)
          parentCtx = parentRoot.Context;

        root = Src.StartActivity($"process:{pid}", ActivityKind.Internal, parentCtx);
        if (root != null) RootsByPid[pid] = root;
      }
      return root;
    }

    private static void Main()
    {
      var id = WindowsIdentity.GetCurrent();
      if (id == null || !new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator))
      {
        Console.WriteLine("관리자 권한으로 실행해 주십시오.");
        return;
      }

      Env.TraversePath().Load();

      var endpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT")
                   ?? Env.GetString("OTEL_EXPORTER_OTLP_ENDPOINT");

    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        throw new InvalidOperationException($"Invalid OTLP endpoint: {endpoint}");

    // ▼ 지역 변수로 생성해서 프로그램 종료 시 자동 Dispose
    using var Otel = Sdk.CreateTracerProviderBuilder()
        .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService("event-agent"))
        .AddSource("event.agent")
        .AddOtlpExporter(o =>
        {
            o.Endpoint = uri;
            o.Protocol = OtlpExportProtocol.Grpc;
        })
        .Build();


      Console.OutputEncoding = System.Text.Encoding.UTF8;

      using var session = new TraceEventSession(SessionName) { StopOnDispose = true };
      session.EnableProvider(SysmonProvider, SysmonLevel, SysmonKeywords);
      session.Source.Dynamic.All += HandleSysmon;

      var etwThread = new Thread(() => session.Source.Process())
      { IsBackground = true, Name = "Sysmon-ETW-Thread" };
      etwThread.Start();

      using var secWatcher = StartSecurityWatcher();

      Console.WriteLine("Event Agent (Sysmon + Security) 실행 중 …  <Enter> 종료");
      Console.ReadLine();

      secWatcher.Enabled = false;
      session.Dispose();
      Otel.Dispose();
      etwThread.Join();
    }

    /* ────────────────────────────── Sysmon ──────────────────────────── */
    private static void HandleSysmon(TraceEvent ev)
    {
      int eid = (int)ev.ID;
      if (SysmonSkipIds.Contains(eid)) return;

      int pid = TryGetPayloadInt(ev, "ProcessId") ?? ev.ProcessID;
      int ppid = TryGetPayloadInt(ev, "ParentProcessId") ?? 0;
      if (pid == 0) return;

      if (ppid == 0 && LastParent.TryGetValue(pid, out var cached)) ppid = cached;
      if (ppid != 0) LastParent[pid] = ppid;

      var root = GetOrCreateRoot(pid, ppid);
      if (root == null) return;

      string? image = TryGetPayloadString(ev, "Image") ?? TryGetPayloadString(ev, "TargetImage");
      var spanName = BuildSpanName(image, eid);

      using var child = Src.StartActivity(spanName, ActivityKind.Internal, parentContext: root.Context);
      if (child != null) AddSysmonTags(child, ev, pid, ppid);

      // 디버깅 로그 
      Console.WriteLine($"[Sysmon] EID={(int)ev.ID} PID={pid} PPID={ppid}");

      // 종료 이벤트(EID=5)면 루트 정리
      if (eid == 5)
      {
        root.Stop();
        RootsByPid.TryRemove(pid, out _);
      }
    }

    private static string? TryGetPayloadString(TraceEvent ev, string field)
    {
      if (ev.PayloadNames?.Contains(field) == true)
      {
        try { return ev.PayloadByName(field)?.ToString(); } catch { }
      }
      return null;
    }

    private static int? TryGetPayloadInt(TraceEvent ev, string field)
    {
      if (ev.PayloadNames?.Contains(field) == true)
      {
        try
        {
          object? val = ev.PayloadByName(field);
          return val switch
          {
            int i => i,
            long l => (int)l,
            string s when int.TryParse(s, out var x) => x,
            _ => (int?)null
          };
        }
        catch { }
      }
      return null;
    }

    /* ───────────────────────────── Security ─────────────────────────── */
    private static EventLogWatcher StartSecurityWatcher()
    {
      string xpath = "*[System[(" + string.Join(" or ", SecurityEventIds.Select(id => $"EventID={id}")) + ")]]";
      var query = new EventLogQuery("Security", PathType.LogName, xpath)
      {
        TolerateQueryErrors = true,
        ReverseDirection = false
      };

      var watcher = new EventLogWatcher(query, null, false);
      watcher.EventRecordWritten += (_, e) =>
      {
        if (e.EventRecord == null) return;
        try { HandleSecurity(e.EventRecord); }
        finally { e.EventRecord.Dispose(); }
      };
      watcher.Enabled = true;
      Console.WriteLine("Security EventLogWatcher 시작됨.");
      return watcher;
    }

    private static void HandleSecurity(EventRecord rec)
    {
      using (rec)
      {
        int pid = 0, ppid = 0;
        string pidSource = "unknown";

        switch (rec.Id)
        {
          case 4688: // 프로세스 생성
            pid = ToPid(GetSecurityDataAny(rec, "NewProcessId", "ProcessId"));
            ppid = ToPid(GetSecurityDataAny(rec, "ParentProcessId", "CreatorProcessId", "ProcessId"));
            pidSource = (pid != 0) ? "clientpid" : "unknown";
            break;

          case 4689: // 프로세스 종료
            pid = ToPid(GetSecurityDataAny(rec, "ProcessId", "NewProcessId"));
            ppid = 0;
            pidSource = "terminate";
            break;

          case 4697: // 서비스 설치
            pid = ToPid(GetSecurityDataAny(rec, "ClientProcessId", "ProcessId", "CallerProcessId"));
            ppid = ToPid(GetSecurityDataAny(rec, "ParentProcessId", "CallerParentProcessId"));
            pidSource = (pid != 0) ? "clientpid" : "provider";
            break;

          // 로그인/권한/실패 등
          case 4624:
          case 4625:
          case 4648:
          case 4672:
            pid = ToPid(GetSecurityDataAny(rec, "ProcessId", "ClientProcessId", "CallerProcessId"));
            pidSource = (pid != 0) ? "clientpid" : "unknown";
            break;

          default:
            pid = ToPid(GetSecurityDataAny(rec, "ProcessId", "ClientProcessId", "CallerProcessId"));
            ppid = ToPid(GetSecurityDataAny(rec, "ParentProcessId", "CreatorProcessId", "CallerParentProcessId"));
            pidSource = (pid != 0) ? "clientpid" : "unknown";
            break;
        }

        if (pid == 0) pid = rec.ProcessId ?? 0;
        if (pid == 0) return;

        if (ppid == 0 && LastParent.TryGetValue(pid, out var cached)) ppid = cached;
        if (ppid != 0) LastParent[pid] = ppid;

        // 디버깅 로그
        Console.WriteLine($"[Security] EID={rec.Id} PID={pid} PPID={ppid} src={pidSource}");

        var root = GetOrCreateRoot(pid, ppid);
        if (root == null) return;

        var img = GetImageFromEventRecord(rec);
        var spanName = BuildSpanName(img, rec.Id);

        using var span = Src.StartActivity(spanName, ActivityKind.Internal, root.Context);
        if (span == null) return;

        AddETWTags(span, rec, pid, ppid);

        if (rec.Id == 4689)
        {
          root.Stop();
          RootsByPid.TryRemove(pid, out _);
        }
      }
    }

    /* ────── 스팬 네이밍 ────── */
    private static string BuildSpanName(string? imagePath, int eventId)
    {
      string name = "unknown";
      if (!string.IsNullOrWhiteSpace(imagePath))
      {
        try { name = Path.GetFileName(imagePath); } catch { name = imagePath!; }
        if (string.IsNullOrWhiteSpace(name)) name = imagePath!;
      }
      return $"{name}@evt:{eventId}";
    }

    private static string? GetImageFromEventRecord(EventRecord rec)
    {
      string? v = GetSecurityDataAny(rec, "NewProcessName", "Image", "ProcessName", "Application", "ServiceFileName");
      if (!string.IsNullOrWhiteSpace(v)) return v;

      var cmd = GetSecurityDataAny(rec, "CommandLine", "Command");
      if (!string.IsNullOrWhiteSpace(cmd))
      {
        var s = cmd.Trim();
        if (s.StartsWith("\""))
        {
          int end = s.IndexOf('"', 1);
          if (end > 1) return s.Substring(1, end - 1);
        }
        var first = s.Split(new[] { ' ' }, 2)[0];
        if (!string.IsNullOrWhiteSpace(first)) return first;
      }
      return null;
    }

    private static void AddSysmonTags(Activity span, TraceEvent ev, int pid, int ppid)
    {
      Tag(span, "channel", "Sysmon");
      Tag(span, "EventName", ev.EventName);
      Tag(span, "sysmon.ppid", ppid);
      Tag(span, "ID", (int)ev.ID);
      Tag(span, "TimeStamp", ev.TimeStamp);
      Tag(span, "sysmon.opcode", ev.Opcode);
      Tag(span, "ProviderGuid", ev.ProviderGuid);

      foreach (var n in ev.PayloadNames ?? Array.Empty<string>())
        try { Tag(span, n, ev.PayloadByName(n)); } catch { }
    }

    private static void AddETWTags(Activity span, EventRecord rec, int pid, int ppid)
{
    var bag = ParseEventXml(rec, out int eid, out string channel, out DateTime? systemUtc, out long? recordId);

    Tag(span, "channel", string.IsNullOrEmpty(channel) ? "Security" : channel);
    Tag(span, "proc.pid", pid);
    Tag(span, "proc.ppid", ppid);
    Tag(span, "event.id", rec.Id);
    Tag(span, "record.id", rec.RecordId);

    // TimeStamp만 사용 (UtcTime 미사용)
    TagTimeStamp(span, systemUtc, rec.TimeCreated);

    // 호환을 위해 유지하는 키들
    Tag(span, "ID", rec.Id);
    if (rec.ProviderId != null) Tag(span, "ProviderGuid", rec.ProviderId.Value.ToString("D"));

    // opcode (표시명 우선, 없으면 숫자)
    try
    {
        var op = rec.OpcodeDisplayName ?? rec.Opcode.ToString();
        if (!string.IsNullOrWhiteSpace(op)) Tag(span, "opcode", op);
    }
    catch { /* 일부 OS에서 표시명 미지원일 수 있음 */ }

    // 이벤트 이름 정규화
    Tag(span, "EventName", EventNameFor(eid));

    // 공통 유저/무결성 태깅
    MaybeTagUserAndLogon(span, bag);
    MaybeTagIntegrity(span, bag);

    // 이벤트별 매핑
    switch (eid)
    {
        case 4688: Map4688(span, bag); break;
        case 4689: Map4689(span, bag); break;
        case 4697: Map4697(span, bag); break;
        case 4698: Map4698(span, bag); break;
        case 4699: Map4699(span, bag); break;
        case 4624: Map4624(span, bag); break;
        case 4625: Map4625(span, bag); break;
        case 4648: Map4648(span, bag); break;
        case 4672: Map4672(span, bag); break;
        default:   MapDefault(span, bag); break;
    }

    // Sysmon-like ProcessGuid 생성(이름 통일: ProcessGuid만 사용)
    var startKeyStr = GetFirst(bag, "ClientProcessStartKey", "ProcessStartKey");
    var processGuid = BuildSysmonLikeProcessGuid(systemUtc, startKeyStr, pid, ppid, recordId);
    if (!string.IsNullOrEmpty(processGuid))
    {
        Tag(span, "ProcessGuid", processGuid);
        // sysmonlike.* 및 process_guid 등은 더 이상 태깅하지 않음
        Tag(span, "method", string.IsNullOrEmpty(startKeyStr) ? "fallback_hash" : "with_startkey");
    }

    // 풀패스/전체 인자 재구성
    EnrichImageAndCommandLine(span, bag);

    // 이미 정규화/복제한 원본 키들은 제외하고 나머지 원본 드롭인
    var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "TaskName","ClientProcessId","ParentProcessId","ProcessId",
        "CallerProcessId","CreatorProcessId","CallerParentProcessId",
        "SubjectUserName","SubjectLogonId","ProcessCommandLine","CommandLine",
        "NewProcessName","ProcessName","__MAPPED.Image", "UtcTime"
    };

    foreach (var (k, v) in bag)
    {
        if (string.IsNullOrWhiteSpace(k) || v is null) continue;
        if (covered.Contains(k)) continue;
        Tag(span, k, v);
    }

    // ▼ 필요 시 Security 원본을 sec.* 네임스페이스로 넘길 수 있는 옵션(주석 유지)
    /*
    foreach (var (k, v) in bag)
        if (!string.IsNullOrWhiteSpace(k) && !string.IsNullOrWhiteSpace(v))
            Tag(span, $"sec.{k}", v);
    */
}


    private static string EventNameFor(int id) => id switch
    {
      4688 => "ProcessCreate",
      4689 => "ProcessTerminate",
      4697 => "ServiceInstall",
      4698 => "ScheduledTaskCreated",
      4699 => "ScheduledTaskDeleted",
      4624 => "LogonSuccess",
      4625 => "LogonFailure",
      4648 => "LogonExplicitCreds",
      4672 => "SpecialPrivilegesAssigned",
      _ => $"Event{id}"
    };
    private static void EnrichImageAndCommandLine(Activity span, IDictionary<string,string> bag)
{
    var originalCmd = GetFirst(bag, "CommandLine", "ProcessCommandLine", "Command");
    if (!string.IsNullOrWhiteSpace(originalCmd))
        Tag(span, "evt.Command", originalCmd);

    var rawImg = GetFirst(bag, "__MAPPED.Image", "Image", "NewProcessName", "ProcessName", "Command");
    if (string.IsNullOrWhiteSpace(rawImg)) return;

    var wd = GetFirst(bag, "CurrentDirectory", "WorkingDirectory");

    // 풀패스 해상 (전역 3인자 메서드 사용)
    var fullImg = ResolveExecutableFullPath(rawImg, wd, out var howResolved);
    TagOverwrite(span, "Image", fullImg);                    // ← finalImg -> fullImg
    if (!string.IsNullOrWhiteSpace(howResolved))
        Tag(span, "resolution.method", howResolved);
    if (!string.IsNullOrWhiteSpace(wd))
        TagIfEmpty(span, "CurrentDirectory", wd);

    // 전체 인자 재조립 (풀패스 + 원본 인자)
    var args = ExtractArgsFromCommandLine(originalCmd);
    var rebuilt = string.IsNullOrWhiteSpace(args) ? $"\"{fullImg}\"" : $"\"{fullImg}\" {args}";
    TagOverwrite(span, "CommandLine", rebuilt);
}


    // 실행 파일 풀패스 탐색: 절대경로면 그대로, 아니면 WD→System32→PATH 순
    static string ResolveExecutableFullPath(string cmd, string? workingDir, out string method)
{
    method = "";
    if (string.IsNullOrWhiteSpace(cmd)) return "";

    var name = cmd.Trim().Trim('"');

    // 절대경로면 그대로
    if (Path.IsPathRooted(name) && File.Exists(name)) { method = "as_is"; return name; }

    // 1) WorkingDirectory 우선
    if (!string.IsNullOrWhiteSpace(workingDir))
    {
        foreach (var c in Candidates(workingDir!, name))
            if (File.Exists(c)) { method = "from_working_dir"; return c; }
    }

    // 2) System32
    var sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
    foreach (var c in Candidates(sys32, name))
        if (File.Exists(c)) { method = "from_system32"; return c; }

    // 3) PATH
    var paths = (Environment.GetEnvironmentVariable("PATH") ?? "")
        .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
    foreach (var p in paths)
        foreach (var c in Candidates(p.Trim(), name))
            if (File.Exists(c)) { method = "from_path"; return c; }

    method = "unresolved";
    return name;

    static IEnumerable<string> Candidates(string dir, string baseName)
    {
        var exts = new[] { "", ".exe", ".cmd", ".bat", ".com" };
        foreach (var ext in exts)
            yield return Path.Combine(dir, baseName.EndsWith(ext, StringComparison.OrdinalIgnoreCase) ? baseName : baseName + ext);
    }
}


    // 기존 CommandLine에서 인자부만 추출(선두 실행파일 제외)
    private static string ExtractArgsFromCommandLine(string cmdline)
    {
      if (string.IsNullOrWhiteSpace(cmdline)) return null;
      var s = cmdline.Trim();
      if (s.StartsWith("\""))
      {
        var end = s.IndexOf('"', 1);
        if (end > 0 && end + 1 < s.Length) return s.Substring(end + 1).TrimStart();
        return null;
      }
      var first = s.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
      return (first.Length == 2) ? first[1] : null;
    }

    // ──────────────────────────────────────────────────────────────────────
    // Sysmon-like ProcessGuid 생성 (Guid "D" 포맷)
    // ──────────────────────────────────────────────────────────────────────
    private static string BuildSysmonLikeProcessGuid(DateTime? utc, string startKey, int pid, int ppid, long? recordId)
    {
      try
      {
        var machinePart = Crc32OfString(GetMachineGuidOrFallback());           // 4B
        var timePart = (uint)(utc.HasValue ? new DateTimeOffset(utc.Value).ToUnixTimeSeconds()
                                              : DateTimeOffset.UtcNow.ToUnixTimeSeconds()); // 4B
        var typeMask = 0x10000000u;                                         // 4B (프로세스 마스크 유사)
        uint tailPart;

        if (!string.IsNullOrWhiteSpace(startKey) && ulong.TryParse(startKey, out var sk))
          tailPart = (uint)(sk & 0xffffffff);
        else
          tailPart = Fnv1a32($"{pid}|{ppid}|{recordId ?? 0}");

        // 16바이트(빅엔디안) → Guid
        var bytes = new byte[16];
        WriteBE(machinePart, bytes, 0);
        WriteBE(timePart, bytes, 4);
        WriteBE(typeMask, bytes, 8);
        WriteBE(tailPart, bytes, 12);
        return new Guid(bytes).ToString("D");
      }
      catch { return null; }
    }

    private static void WriteBE(uint v, byte[] b, int off)
    {
      b[off + 0] = (byte)((v >> 24) & 0xff);
      b[off + 1] = (byte)((v >> 16) & 0xff);
      b[off + 2] = (byte)((v >> 8) & 0xff);
      b[off + 3] = (byte)(v & 0xff);
    }

    private static string GetMachineGuidOrFallback()
    {
      try
      {
        // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
        using var rk = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        var v = rk?.GetValue("MachineGuid")?.ToString();
        if (!string.IsNullOrWhiteSpace(v)) return v;
      }
      catch { }
      return Environment.MachineName; // 폴백(충분히 안정적)
    }

    private static uint Crc32OfString(string s)
    {
      unchecked
      {
        uint crc = 0xFFFFFFFF;
        foreach (var ch in System.Text.Encoding.UTF8.GetBytes(s))
        {
          crc ^= ch;
          for (int i = 0; i < 8; i++)
            crc = ((crc & 1) != 0) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
        }
        return ~crc;
      }
    }

    private static uint Fnv1a32(string s)
    {
      unchecked
      {
        uint hash = 2166136261;
        foreach (var b in System.Text.Encoding.UTF8.GetBytes(s))
        {
          hash ^= b;
          hash *= 16777619;
        }
        return hash;
      }
    }
    private static string? GetSecurityData(EventRecord rec, string fieldName)
    {
      try
      {
        var xml = new XmlDocument();
        xml.LoadXml(rec.ToXml());
        var node = xml.SelectSingleNode($"//*[local-name()='Data' and @Name='{fieldName}']");
        return string.IsNullOrWhiteSpace(node?.InnerText) ? null : node.InnerText;
      }
      catch { return null; }
    }

    private static string? GetSecurityDataAny(EventRecord rec, params string[] names)
    {
      foreach (var n in names)
      {
        var v = GetSecurityData(rec, n);
        if (!string.IsNullOrWhiteSpace(v)) return v;
      }
      return null;
    }

    private static int ToPid(string? s)
    {
      if (string.IsNullOrWhiteSpace(s)) return 0;
      var t = s.Trim();
      if (int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec)) return dec;
      if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) t = t[2..]; // ← t로 슬라이스
      return int.TryParse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex) ? hex : 0;
    }

    private static void Tag(Activity span, string k, object? v)
    {
      if (v != null) span.SetTag(k, v);
    }
    static void Map4688(Activity span, IDictionary<string, string> bag)
    {
      // Image
      var img = GetFirst(bag, "NewProcessName", "Image", "ProcessName");
      MapImage(span, bag, img);

      // CommandLine (정책 필요)
      var cmd = GetFirst(bag, "ProcessCommandLine", "CommandLine");
      if (!string.IsNullOrWhiteSpace(cmd)) Tag(span, "CommandLine", cmd);

      // PID/PPID는 공통 단계에서 이미 처리
    }

    static void Map4689(Activity span, IDictionary<string, string> bag)
    {
      // 종료 이벤트 → ProcessId만 확실히
      var pid = TryParsePid(GetFirst(bag, "ProcessId", "NewProcessId"));
      if (pid != null) Tag(span, "ProcessId", pid.Value);
    }

    static void Map4697(Activity span, IDictionary<string, string> bag)
    {
      // 서비스 설치: 환경에 따라 ClientProcessId/ParentProcessId가 없을 수 있음
      var svcFile = GetFirst(bag, "ServiceFileName");
      if (!string.IsNullOrWhiteSpace(svcFile))
      {
        MapImage(span, bag, svcFile);
        // 가끔 ServiceFileName에 인자가 함께 들어오기도 함 → 보조적으로 CommandLine에 복제
        TagIfEmpty(span, "CommandLine", svcFile);
      }
      // 참고 정보는 evt.*로 남기는 편이 안전: ServiceName, StartType 등
    }

    static void Map4698(Activity span, IDictionary<string, string> bag)
{
    var tc = GetFirst(bag, "TaskContent");
    if (TryParseTaskContent(tc, out var cmd, out var args, out var wd))
    {
        var fullPath = ResolveExecutableFullPath(cmd, wd, out var how);
        if (!string.IsNullOrWhiteSpace(fullPath))
        {
            Tag(span, "Image", fullPath);
            var quoted = fullPath.Contains(' ') ? $"\"{fullPath}\"" : fullPath;
            var full   = string.IsNullOrWhiteSpace(args) ? quoted : $"{quoted} {args}";
            Tag(span, "CommandLine", full);
            if (!string.IsNullOrWhiteSpace(how)) Tag(span, "method", how); // sysmonlike.* → method
        }
        if (!string.IsNullOrWhiteSpace(wd)) Tag(span, "CurrentDirectory", wd);
    }

    var tname = GetFirst(bag, "TaskName");
    if (!string.IsNullOrWhiteSpace(tname)) Tag(span, "TaskName", tname);

    var linkPid = TryParsePid(GetFirst(bag, "ClientProcessId","ProcessId"));
    if (linkPid != null) Tag(span, "link.pid", linkPid.Value);
}


    static void Map4699(Activity span, IDictionary<string, string> bag)
    {
      // 예약 작업 삭제: TaskContent가 있을 때만 시도
      var tc = GetFirst(bag, "TaskContent");
      if (TryParseTaskContent(tc, out var cmd, out var args, out var wd))
      {
        MapImage(span, bag, cmd);
        var full = string.IsNullOrWhiteSpace(args) ? cmd : $"{cmd} {args}";
        if (!string.IsNullOrWhiteSpace(full)) Tag(span, "CommandLine", full);
        if (!string.IsNullOrWhiteSpace(wd)) Tag(span, "CurrentDirectory", wd);
      }

      var tname = GetFirst(bag, "TaskName");
      if (!string.IsNullOrWhiteSpace(tname)) Tag(span, "TaskName", tname);
      var linkPid = TryParsePid(GetFirst(bag, "ClientProcessId", "ProcessId"));
      if (linkPid != null) Tag(span, "link.pid", linkPid.Value);
    }

    static void Map4624(Activity span, IDictionary<string, string> bag)
    {
      // 로그온 성공
      var img = GetFirst(bag, "ProcessName");
      MapImage(span, bag, img);
      var pid = TryParsePid(GetFirst(bag, "ProcessId"));
      if (pid != null) Tag(span, "ProcessId", pid.Value);

      var lg = GetFirst(bag, "LogonGuid");
      if (!string.IsNullOrWhiteSpace(lg)) Tag(span, "LogonGuid", lg);
    }

    static void Map4625(Activity span, IDictionary<string, string> bag)
    {
      // 로그온 실패: Caller*
      var img = GetFirst(bag, "CallerProcessName", "ProcessName");
      MapImage(span, bag, img);
      var pid = TryParsePid(GetFirst(bag, "CallerProcessId", "ProcessId"));
      if (pid != null) Tag(span, "ProcessId", pid.Value);
    }

    static void Map4648(Activity span, IDictionary<string, string> bag)
    {
      var img = GetFirst(bag, "ProcessName");
      MapImage(span, bag, img);
      var pid = TryParsePid(GetFirst(bag, "ProcessId"));
      if (pid != null) Tag(span, "ProcessId", pid.Value);

      // 대상 사용자도 정보성으로 원본 네임스페이스에 보존
      var tu = GetFirst(bag, "TargetUserName");
      if (!string.IsNullOrWhiteSpace(tu)) Tag(span, "evt.TargetUserName", tu);
    }

    static void Map4672(Activity span, IDictionary<string, string> bag)
    {
      // 특권 할당: User/LogonId만 의미 있음
      var priv = GetFirst(bag, "PrivilegeList");
      if (!string.IsNullOrWhiteSpace(priv)) Tag(span, "evt.PrivilegeList", priv);
      // ProcessId는 대개 없음 → 공통 PID 단계에서 못 구했으면 비움 유지
    }

    static void MapDefault(Activity span, IDictionary<string, string> bag)
    {
      // 보편적 보강: Image/CommandLine가 보이면 표준 키로
      var img = GetFirst(bag, "Image", "NewProcessName", "ProcessName", "Command", "Application");
      MapImage(span, bag, img);

      var cmd = GetFirst(bag, "CommandLine", "ProcessCommandLine", "Command");
      if (!string.IsNullOrWhiteSpace(cmd)) Tag(span, "CommandLine", cmd);

      var wd = GetFirst(bag, "CurrentDirectory", "WorkingDirectory");
      if (!string.IsNullOrWhiteSpace(wd)) Tag(span, "CurrentDirectory", wd);
    }
    static Dictionary<string, string> ParseEventXml(EventRecord rec, out int eventId, out string channel, out DateTime? systemUtc, out long? recordId)
    {
      var bag = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      eventId = 0; channel = rec.LogName ?? ""; systemUtc = rec.TimeCreated?.ToUniversalTime(); recordId = rec.RecordId;

      try
      {
        var doc = new XmlDocument();
        doc.LoadXml(rec.ToXml());

        // System 헤더
        var nEvent = doc.SelectSingleNode("/*[local-name()='Event']");
        var nSystem = nEvent?.SelectSingleNode("./*[local-name()='System']");
        if (nSystem != null)
        {
          eventId = ToInt(nSystem.SelectSingleNode("./*[local-name()='EventID']")?.InnerText) ?? eventId;
          channel = nSystem.SelectSingleNode("./*[local-name()='Channel']")?.InnerText ?? channel;

          var nTime = nSystem.SelectSingleNode("./*[local-name()='TimeCreated']");
          var sysTime = (nTime as XmlElement)?.GetAttribute("SystemTime");
          if (!string.IsNullOrWhiteSpace(sysTime) && DateTime.TryParse(sysTime, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var dt))
            systemUtc = dt;

          var nRecId = nSystem.SelectSingleNode("./*[local-name()='EventRecordID']")?.InnerText;
          if (long.TryParse(nRecId, out var rid)) recordId = rid;
        }

        // EventData → bag
        foreach (XmlElement e in doc.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']"))
        {
          var key = e.GetAttribute("Name");
          if (string.IsNullOrWhiteSpace(key)) continue;
          bag[key] = e.InnerText ?? string.Empty;
        }
      }
      catch
      {
        // XML 파싱 실패해도 공통 System 필드는 rec에서 가져온 값으로 유지
      }
      return bag;
    }

    static void MaybeTagUserAndLogon(Activity span, IDictionary<string,string> bag)
{
    // 1) Subject* 우선
    var domain = GetFirst(bag, "SubjectDomainName","TargetDomainName","Domain");
    var user   = GetFirst(bag, "SubjectUserName","TargetUserName","User");

    // 2) 없으면 TaskContent의 Author 폴백
    if (string.IsNullOrWhiteSpace(user))
    {
        var author = ExtractAuthorFromTaskContent(GetFirst(bag, "TaskContent"));
        if (!string.IsNullOrWhiteSpace(author))
        {
            if (author.Contains('\\')) // "DOMAIN\User" 그대로 사용
            {
                Tag(span, "User", author.Replace('/', '\\'));
                goto EXIT;
            }
            else
            {
                user = author; // 도메인 없이 온 경우
            }
        }
    }

    var built = BuildDomainUser(domain, user);
    if (!string.IsNullOrWhiteSpace(built))
        Tag(span, "User", built);

EXIT:
    var lg = GetFirst(bag, "LogonGuid");
    if (!string.IsNullOrWhiteSpace(lg)) Tag(span, "LogonGuid", lg);
}





    static void MaybeTagIntegrity(Activity span, IDictionary<string, string> bag)
    {
      var ml = GetFirst(bag, "MandatoryLabel", "IntegrityLevel");
      if (string.IsNullOrWhiteSpace(ml)) return;

      var norm = MapIntegrity(ml);
      Tag(span, "IntegrityLevel", norm);
    }

    static void MapImage(Activity span, IDictionary<string, string> bag, string imageOrNull)
    {
      if (string.IsNullOrWhiteSpace(imageOrNull)) return;
      Tag(span, "Image", imageOrNull);
      // 내부 버퍼에 저장해 스팬명 보정 단계에서 사용
      bag["__MAPPED.Image"] = imageOrNull;
    }

    static string GetFirst(IDictionary<string, string> bag, params string[] keys)
    {
      foreach (var k in keys)
        if (k != null && bag.TryGetValue(k, out var v) && !string.IsNullOrWhiteSpace(v))
          return v;
      return null;
    }

    static int? TryParsePid(string v)
    {
      var n = TryParseHexOrDecToLong(v);
      if (n == null) return null;
      if (n.Value < 0 || n.Value > int.MaxValue) return null;
      return (int)n.Value;
    }

    static long? TryParseHexOrDecToLong(string v)
    {
      if (string.IsNullOrWhiteSpace(v)) return null;
      v = v.Trim();

      // "0x..." 또는 "0X..." 또는 "0x00001234" 형태
      if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
      {
        if (long.TryParse(v.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
          return hex;
        return null;
      }

      // 보안 로그에 가끔 "0x7FF..." 같은 포인터 문자열도 옴
      if (v.StartsWith("0X", StringComparison.OrdinalIgnoreCase))
      {
        if (long.TryParse(v.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
          return hex;
        return null;
      }

      // 그냥 10진
      if (long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
        return dec;

      return null;
    }

    static int? ToInt(string s)
    {
      if (int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return n;
      return null;
    }

    static bool TryParseTaskContent(string? xml, out string cmd, out string args, out string wd)
{
    cmd = args = wd = string.Empty;
    if (string.IsNullOrWhiteSpace(xml)) return false;

    try
    {
        var doc = LoadXmlRobust(xml);
        string Sel(string x) => doc.SelectSingleNode($"//*[local-name()='{x}']")?.InnerText?.Trim() ?? "";

        cmd  = Sel("Command");
        args = Sel("Arguments");
        wd   = Sel("WorkingDirectory");
    }
    catch
    {
        // 아주 단순 폴백 (네임스페이스 이슈 등)
        cmd  = RegexMatch(xml, "<Command>(.*?)</Command>");
        args = RegexMatch(xml, "<Arguments>(.*?)</Arguments>");
        wd   = RegexMatch(xml, "<WorkingDirectory>(.*?)</WorkingDirectory>");
    }
    return !string.IsNullOrWhiteSpace(cmd);
}

static XmlDocument LoadXmlRobust(string xml)
{
    // \u003c → <  같은 유니코드 이스케이프/HTML 엔티티 정리
    xml = xml.Replace("\\u003c", "<").Replace("\\u003e", ">")
             .Replace("&lt;", "<").Replace("&gt;", ">").Replace("&amp;", "&");
    var doc = new XmlDocument();
    doc.LoadXml(xml);
    return doc;
}

static string RegexMatch(string s, string pattern)
{
    var m = System.Text.RegularExpressions.Regex.Match(s, pattern, System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    return m.Success ? System.Net.WebUtility.HtmlDecode(m.Groups[1].Value.Trim()) : "";
}


    static string MapIntegrity(string val)
    {
      // 입력: "S-1-16-12288" 또는 "High" 등 → 표준 문자열로 수렴
      val = val?.Trim() ?? "";
      if (val.Length == 0) return val;

      // SID 매핑
      if (val.Contains("S-1-16-4096")) return "Low";
      if (val.Contains("S-1-16-8192")) return "Medium";
      if (val.Contains("S-1-16-8448")) return "MediumPlus";
      if (val.Contains("S-1-16-12288")) return "High";
      if (val.Contains("S-1-16-16384")) return "System";
      if (val.Contains("S-1-16-20480")) return "ProtectedProcess";
      if (val.Contains("S-1-16-28672")) return "SecureProcess";

      // 이미 레이블로 온 경우
      return val;
    }

    static void TagIfEmpty(Activity span, string key, string val)
    {
      if (string.IsNullOrWhiteSpace(val)) return;
      // 중복 방지: 이미 같은 키가 있으면 덮지 않음
      if (!HasTag(span, key)) Tag(span, key, val);
    }

    static bool HasTag(Activity span, string key)
    {
      if (span?.TagObjects is null) return false;
      foreach (var kv in span.TagObjects)
        if (kv.Key == key) return true;
      return false;
    }
    static void TagOverwrite(Activity span, string key, string? value)
{
    if (span == null || string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value)) return;
    span.SetTag(key, value);
}
    static void TagOverwrite(Activity span, string key, long value) => span?.SetTag(key, value);
static string BuildDomainUser(string? domain, string? user)
{
    domain = (domain ?? "").Trim();
    user   = (user ?? "").Trim();
    if (string.IsNullOrEmpty(user)) return "";
    if (string.IsNullOrEmpty(domain)) return user;
    return $"{domain}\\{user}";
}

    static string ExtractAuthorFromTaskContent(string? xml)
    {
      if (string.IsNullOrWhiteSpace(xml)) return "";
      try
      {
        var doc = LoadXmlRobust(xml);
        var n = doc.SelectSingleNode("//*[local-name()='RegistrationInfo']/*[local-name()='Author']");
        return n?.InnerText?.Trim() ?? "";
      }
      catch { return ""; }
    }
    static void TagTimeStamp(Activity span, DateTime? systemUtc, DateTime? recTime)
    {
      // systemUtc(ETW System.TimeCreated) 우선, 없으면 rec.TimeCreated
      var t = (systemUtc ?? recTime);
      if (t.HasValue)
      {
        var local = DateTime.SpecifyKind(t.Value, DateTimeKind.Utc).ToLocalTime();
        Tag(span, "TimeStamp", local.ToString("MM/dd/yyyy HH:mm:ss"));
      }
    }
private static string? NormalizeOpcode(EventRecord rec)
{
    try
    {
        if (rec.Opcode == 0) return "Info";
        var s = rec.OpcodeDisplayName ?? rec.Opcode.ToString();
        if (string.Equals(s, "Information", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(s, "정보", StringComparison.OrdinalIgnoreCase))
            return "Info";
        return s;
    }
    catch { return null; }
}



    }
}
