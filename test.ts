const tdec = new TextDecoder();
const tenc = new TextEncoder();

type TestConfig = {
  filename: string;
  input: string;
  output: string;
  report: string;
};

const print = async (s: string) => await Deno.stdout.write(tenc.encode(s));

const extract_test_config = async (filename: string): Promise<TestConfig> => {
  const text = await Deno.readTextFile(filename);
  const lines = text.split("\n");
  const config = { filename, input: "", output: "", report: "" };
  for (const line of lines) {
    if (line.startsWith("// Input: ")) {
      config.input = line.slice("// Input: ".length);
    } else if (line.startsWith("// Output: ")) {
      config.output = line.slice("// Output: ".length);
    } else if (line.startsWith("// Report: ")) {
      config.report = line.slice("// Report: ".length);
    }
  }
  return config;
};

const compile_program = async (filename: string): Promise<number> => {
  let compiler = "gcc";
  if (filename.endsWith(".cc")) {
    compiler = "g++";
  }
  const cmd = new Deno.Command(compiler, {
    args: [filename, "-static"],
  });
  const proc = cmd.spawn();
  const status = await proc.status;
  return status.code;
};

const test_program = async (config: TestConfig) => {
  const exit_code = await compile_program(config.filename);
  if (exit_code != 0) {
    console.error(`Could not compile ${config.filename}`);
    return { good: false, error: "Compilation Failed" };
  }
  await Deno.writeFile(".input", tenc.encode(config.input));
  const cmd = new Deno.Command("./carcer", {
    args: ["./a.out", "-i", ".input", "-o", ".output", "-e", ".error"],
    stdout: "piped",
  });
  const proc = cmd.spawn();
  const cmdOutput = await proc.output();

  // Check report
  const json = JSON.parse(tdec.decode(cmdOutput.stdout));
  if (json.report.trim() != config.report.trim()) {
    return { good: false, json, config };
  }

  // Check output
  const output = await Deno.readTextFile(".output");
  if (config.output && output.trim() != config.output.trim()) {
    return { good: false, json, config, cmdOutput };
  }
  return { good: true };
};

const cleanUp = async () => {
  await Deno.remove(".input");
  await Deno.remove(".output");
  await Deno.remove(".error");
  await Deno.remove("a.out");
};

const errors = [];
for await (const file of Deno.readDir("./test")) {
  if (file.name.endsWith(".c") || file.name.endsWith(".cc")) {
    const config = await extract_test_config(`./test/${file.name}`);
    const testResult = await test_program(config);
    await print(testResult.good ? "." : "X");
    if (!testResult.good) errors.push(testResult);
  }
}
await print("\n");
if (errors.length > 0) {
  console.log(errors);
}
await cleanUp();
