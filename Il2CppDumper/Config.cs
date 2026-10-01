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
        public string PythonExecutable { get; set; } = "python";
        public string WatermarkBrand { get; set; } = "axent.cc";
        public int WatermarkRepeatEveryTypes { get; set; } = 0;
    }
}
