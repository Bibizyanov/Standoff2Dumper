namespace Il2CppDumper
{
    public class Config
    {
        public bool DumpMethod { get; set; } = true;
        public bool DumpField { get; set; } = true;
        public bool DumpProperty { get; set; } = true;
        public bool DumpAttribute { get; set; } = false;
        public bool DumpFieldOffset { get; set; } = true;
        public bool DumpMethodOffset { get; set; } = true;
        public bool DumpTypeDefIndex { get; set; } = true;
        public bool GenerateStruct { get; set; } = true;
        public bool GenerateDummyDll { get; set; } = true;
        public bool DummyDllAddToken { get; set; } = true;
        public string ProtectedMetadataVA { get; set; } = "0x1B60480"; // брать крч sub_63BD060 эта та хуйня шо вызывается для v4 = ((__int64 (__fastcall *)(__int64))sub_63BD060)(a1); shift + f12 - global-metadata.dat и там оно есть на off_BEBD148 заходим и берем унк. off_BEBD148     DCQ unk_1B60480
        public string ProtectedCodeRegistration { get; set; } = "0xB7C32E0"; // 
        public string ProtectedMetadataRegistration { get; set; } = "0xB7C3358"; // чекайте codereg+metareg.png 
        public string ProtectedStringLiteralOffsetsField { get; set; } = "0x160";
        public string ProtectedStringLiteralDataField { get; set; } = "0x138";
        public string ProtectedStringLiteralCountField { get; set; } = "0xFC";
        public string ProtectedStringLiteralOffsetsCountField { get; set; } = "0x44"; // OFFSETS.MD
        public string PythonExecutable { get; set; } = "python";
    }
}
