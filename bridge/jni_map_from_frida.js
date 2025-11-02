// bridge/jni_map_from_frida.js
// Hook RegisterNatives to capture Java<->native mapping
const sym = Module.enumerateExportsSync("libart.so").find(e => /RegisterNatives/.test(e.name));
if (!sym) { console.log("RegisterNatives not found"); }

Interceptor.attach(ptr(sym.address), {
  onEnter(args) {
    this.env = args[0];
    this.jclass = args[1];
    this.methods = args[2];
    this.nMethods = args[3].toInt32();
  },
  onLeave(retval) {
    const count = this.nMethods;
    for (let i = 0; i < count; i++) {
      const base = this.methods.add(i * (Process.pointerSize * 3));
      const name = Memory.readCString(Memory.readPointer(base));
      const sig  = Memory.readCString(Memory.readPointer(base.add(Process.pointerSize)));
      const fn   = Memory.readPointer(base.add(Process.pointerSize * 2));
      console.log(JSON.stringify({ type: "jni", name, sig, fn: fn, addr: fn }));
    }
  }
});
