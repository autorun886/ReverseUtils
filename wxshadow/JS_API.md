# rustFrida JS API 精简参考

> 来源：[rustFrida README - JS API 参考](https://github.com/kkkbbb/rustFrida#js-api-%E5%8F%82%E8%80%83)，整理于 2026-09-19。本文面向 ARM64 Android，仅保留常用入口、语义和重要约束；完整细节以项目 README 为准。

## 1. API 选择

| 目标 | 推荐 API | 原函数行为 |
| --- | --- | --- |
| 观察或修改 native 参数 | `Interceptor.attach(..., { onEnter })` | 自动执行 |
| 观察或修改 native 返回值 | `Interceptor.attach(..., { onLeave })` | 自动执行 |
| 条件跳过或完全替换 native 函数 | `hook()` / `Interceptor.replace()` | 用 `this.$orig()` 手动调用 |
| 高频 native hook | `CModule` + `attachNative()` / `hookNative()` | attach 自动执行；replace 手动执行 |
| 普通 Java hook | `Java.use().method.impl` | 用 `this.$orig()` 手动调用 |
| 高频 Java hook | Managed DSL (`dslImpl`) | 用 `orig()` 手动调用 |
| 查模块、符号、导入导出 | `Module` | - |
| 读写内存 | `ptr()` / `Memory` | - |
| JNI 函数表与结构体 | `Jni` | - |
| 指令跟踪 | `qbdi` | 需启用 QBDI feature |

全局对象：`console`、`ptr()`、`Memory`、`File`、`Module`、`Interceptor`、`CModule`、`hook()`、`hookNative()`、`attachNative()`、`unhook()`、`callNative()`、`NativeFunction`、`qbdi`、`Java`、`Jni`。

常用类型：

```ts
type AddressLike = NativePointer | number | bigint | "0x...";
type ModuleInfo = {
  name: string;
  base: NativePointer;
  size: number;
  path: string;
};
```

## 2. Native Hook

### Interceptor

`Interceptor.attach` 自动执行原函数。`args[n]` 对应 ARM64 的 `xN`，赋值可修改参数；`retval.replace()` 可修改返回值；`this` 可保存跨 `onEnter` / `onLeave` 的状态。

```js
var open = Module.findExportByName("libc.so", "open");

var listener = Interceptor.attach(open, {
    onEnter(args) {
        this.path = args[0].readCString();
        args[1] = ptr(0);              // 修改 x1
    },
    onLeave(retval) {
        console.log(this.path, retval.toInt32());
        if (retval.toInt32() < 0) retval.replace(0);
    }
});

listener.detach();
Interceptor.detachAll();
```

`Interceptor.replace(target, fn, mode?)` 等价于 replace 型 `hook()`，原函数不会自动运行。

### hook / unhook

`hook()` 回调参数前 8 项对应 `x0..x7`，类型为 `BigInt`；`this` 提供 `x0..x30`、`sp`、`pc`、`trampoline` 和 `$orig()`。修改 `this.xN` 后调用 `$orig()`，会使用修改后的寄存器。

```js
hook(target, function(a, b) {
    if (Number(a) === 0) return -1; // 跳过原函数
    this.x1 = 100;
    return this.$orig();            // 调用原函数
}, Hook.NORMAL);

unhook(target);
```

模式：`Hook.NORMAL`（`0`，默认）或 `Hook.WXSHADOW`（`1`；也接受 `true`）。该模式参数同样适用于 `Interceptor.attach/replace`。

### 调用 native 函数

- `callNative(func, ...args)`：仅整数/指针，最多 6 个参数（`x0..x5`）。
- `new NativeFunction(addr, retType, argTypes)`：支持任意签名和浮点参数，最多 256 个栈参数；不支持 struct-by-value。
- 类型包括 `void`、整数类型、`pointer`、`float`、`double`、`size_t` / `ssize_t`。

```js
var openFn = new NativeFunction(open, "int", ["pointer", "int"]);
var fd = openFn(Memory.allocUtf8String("/tmp/foo"), 0);
```

### CModule 高频回调

`CModule` 使用内置 TinyCC 在目标进程编译 C。对象持有代码内存，hook 存活期间必须保留 JS 引用。

```js
var cm = new CModule(`
    #include <rfhook.h>
    void on_enter(HookContext *ctx, void *data) { ctx->x[1] = 0; }
    void on_leave(HookContext *ctx, void *data) {
        if ((int64_t)ctx->x[0] < 0) ctx->x[0] = 0;
    }
`);
globalThis.keepCm = cm;

attachNative(open, {
    onEnter: cm.on_enter,
    onLeave: cm.on_leave,
    data: ptr(0),
    mode: Hook.NORMAL
});
```

- `attachNative(target, { onEnter?, onLeave?, data?, mode? })`：自动执行原函数；只有 `onEnter` 时走快速路径。
- `hookNative(target, callback, data?, mode?)`：replace 语义；C 中用 `hook_invoke_trampoline(ctx, ctx->trampoline)` 调原函数。
- C 回调签名：`void callback(HookContext *ctx, void *user_data)`。
- `ctx->x[0..30]` 是寄存器；`onLeave` 时 `x0` 是返回值。

## 3. Java Hook

### 常规用法

Spawn 模式下必须放进 `Java.ready()`。实例方法中的 `this` 是对象代理，静态方法中是 class 载体。

```js
Java.ready(function () {
    var Log = Java.use("android.util.Log");
    var info = Log.i.overload("java.lang.String", "java.lang.String");

    info.impl = function (tag, msg) {
        console.log(tag, msg, this.$className);
        return this.$orig(tag, msg);
    };

    // 取消：info.impl = null;
});
```

核心规则：

- 构造函数：`Class.$new(...)`；构造方法 hook：`Class.$init.impl = fn`。
- 指定重载：`method.overload("java.lang.String", ...)`，也可用 JNI 签名。
- 字段必须通过 `.value` 读写：`obj.field.value`。
- 字段与方法同名时，`obj.name()` 调方法，`obj.name.value` 访问字段。
- `$orig()` 不传参数时复用原参数；传参时使用新参数。

### Managed DSL

DSL 把受限的 JS/Java 风格代码编译成 dex callback，适合高频方法。目标必须有独立 quick entrypoint；必要时先执行 `method.opt("auto")` 或 `method.compile("auto")`。

```js
var HashMap = Java.use("java.util.HashMap");
var put = HashMap.put.overload("java.lang.Object", "java.lang.Object");

put.opt("auto");
put.dsl({ buff: 4096 }).dslImpl = `
    count("put");
    if ((this.size() & 1023) == 0) send("size", this.size());
    return orig(arg0, arg1);
`;

var messages = put.dslRead(64);
```

DSL 内置 `this`、`arg0...`、`orig()`、`count()`、`send()`；支持变量、字段/方法调用、对象/数组、条件、循环、`switch`、`try/catch`。它不是完整 JS runtime，不能访问 JS 闭包、`console`、定时器或 Promise。`send()` 仅接受 `int` 或 `java.lang.String`；缓冲区满时丢弃新消息而不阻塞。

### 实例、ClassLoader 与执行模式

```js
Java.choose("android.app.Activity", {
    onMatch(instance) { console.log(instance.$className); },
    onComplete() {},
    subtypes: true,
    maxCount: 1000
});

var loaders = Java.classLoaders();
Java.setClassLoader(loaders[0]);
var Cls = Java.findClassWithLoader(loaders[0], "com.example.MyClass");
```

- `Java.choose` 的对象代理只在 `onMatch` 执行期间有效；跨回调使用前应复制所需值或自行创建全局引用。
- Spawn 模式下 ClassLoader 相关操作也应放在 `Java.ready()` 中。
- `Java.setStealth(mode)` 必须在安装 `.impl` 之前调用；`Java.getStealth()` 返回当前模式。
- Deopt：`Java.deopt()`、`deoptimizeBootImage()`、`deoptimizeEverything()`、`deoptimizeMethod(cls, method, sig)`。

### Java / JS 类型转换

- Java 基本类型转为 JS `boolean` / `number`，`long` 转 `BigInt`，`String` 转 JS string，其他对象保留代理。
- Java 装箱类型不会自动拆箱，使用 `.intValue()`、`.doubleValue()` 等。
- Java 容器不会展开，须通过其 Java 方法遍历。
- JS string 可转为 Java `String`；Java 对象参数接受带 `__jptr` 的 wrapper / Proxy。
- JS number、boolean、bigint 可按目标签名自动装箱；JS 数组可递归转换为 Java 基本类型数组或对象数组。
- `null` / `undefined` 转 JNI null；建议显式使用 `null`。

## 4. JNI

```js
var registerNatives = Jni.addr("RegisterNatives");
var entry = Jni.find("FindClass");       // { name, index, address }
var env = Jni.env.ptr;

var cls = Jni.env.findClass("java/lang/String");
var name = Jni.env.getClassName(cls);
var methods = Jni.structs.JNINativeMethod.readArray(addr, count);
```

常用入口：

| API | 作用 |
| --- | --- |
| `Jni.addr(name)` / `Jni.addr(env, name)` | 获取 JNI 函数地址 |
| `Jni.find(name)` / `Jni.entries()` / `Jni.table` | 查询 JNI 函数表 |
| `Jni.env.getClassName()` / `getObjectClassName()` | 获取类名 |
| `Jni.env.readJString()` / `newStringUtf()` | 转换字符串 |
| `Jni.env.findClass()` | 查找类 |
| `Jni.env.newLocalRef()` / `deleteLocalRef()` | 管理局部引用 |
| `Jni.env.exceptionCheck/Clear/Occurred()` | 管理 JNI 异常 |
| `Jni.structs.JNINativeMethod.readArray()` | 解析 native 方法数组 |
| `Jni.structs.jvalue.readArray()` | 解析 `jvalue` 数组 |

引用参数接受 `NativePointer`、`BigInt`、十六进制字符串或 `{ __jptr }` wrapper。`Jni.env.*` 可将 `envPtr` 作为可选首参；省略时自动 attach 当前线程。调用失败后的 JNI 异常会被清理。

## 5. 内存与指针

`Memory.readXxx(addr)` 与 `ptr(addr).readXxx()` 等价，推荐指针链式写法。

```js
var p = ptr("0x7f12345678");
var value = p.add(8).readPointer().readU32();
p.writeU64(0xdeadbeefn);

var buf = Memory.alloc(16);              // RWX、零初始化，随 GC 释放
var str = Memory.allocUtf8String("hello");
Memory.flushCodeCache(buf, 16);           // 写入代码后必须刷新 I-cache
```

主要 API：

- 指针：`ptr()`、`add()`、`sub()`、`toString()`、`toJSON()`、`toInt()` / `toNumber()`。
- 读取：`readU8/U16/U32/U64()`、`readPointer()`、`readCString()`、`readUtf8String()`、`readByteArray()`。
- 写入：`writeU8/U16/U32/U64()`、`writePointer()`、`writeBytes()`、`writest()`。
- 管理：`Memory.alloc()`、`allocUtf8String()`、`protect()`、`flushCodeCache()`。

约束：无效地址抛 `RangeError`；`readCString` 最多读取 4096 字节；普通 `writeXxx` 不自动修改页权限。写只读段前先 `Memory.protect()`。

Patch 行为：

| API | 用途 |
| --- | --- |
| `writeBytes(bytes, 0)` | 普通可见写入 |
| `writeBytes(bytes, 1)` | WXSHADOW 短 patch，单页内，内存读取仍见原字节 |
| `writest(bytes)` | 将一条 ARM64 指令替换为多条，自动处理常见 PC-relative 指令 |
| `unhook(addr)` | 清理 hook、`writest` 或 stealth `writeBytes` patch |

## 6. Module

| API | 作用 |
| --- | --- |
| `findExportByName(module, symbol)` | 查导出地址 |
| `findBaseAddress(module)` | 查模块基址 |
| `findByAddress(addr)` | 地址反查模块 |
| `enumerateModules()` | 枚举模块 |
| `enumerateExports/Imports/Symbols(name)` | 枚举 ELF 信息 |
| `enumerateRanges(name, prot?)` | 按权限枚举内存范围 |
| `load(path, flagsOrTagged?, tagged?)` | 运行时加载 SO |

枚举信息来自磁盘 ELF，无文件支撑的模块可能返回空数组。`Module.load()` 默认使用 `RTLD_NOW`；布尔 `true` 或第三参数 `true` 启用 memfd tagged 加载，模块在 maps 中显示为 `wwb_...`。

## 7. File 与 console

```js
console.log("loaded");
File.writeAllText("/data/local/tmp/demo.txt", "hello\n");
var text = File.readAllText("/data/local/tmp/demo.txt");

var f = new File("/data/local/tmp/data.bin", "rb");
var data = f.readBytes();
f.close();
```

- 日志：`console.log/info/warn/error/debug(...)`。
- 整体文件：`File.readAllBytes/Text()`、`File.writeAllBytes/Text()`。
- 流式文件：`readBytes()`、`readText()`、`readLine()`、`write()`、`tell()`、`seek()`、`flush()`、`close()`。
- 定位常量：`File.SEEK_SET`、`File.SEEK_CUR`、`File.SEEK_END`。API 为同步调用，长脚本应显式关闭文件。

## 8. QBDI Trace

典型生命周期：创建 VM -> 添加插桩范围 -> 分配虚拟栈 -> 设置调用现场 -> 注册 trace -> 执行 -> 读取寄存器 -> 销毁。

```js
var vm = qbdi.newVM();
qbdi.addInstrumentedModuleFromAddr(vm, target);
qbdi.allocateVirtualStack(vm, 0x100000);
qbdi.simulateCall(vm, 0, arg0, arg1);
qbdi.registerTraceCallbacks(vm, target);
qbdi.run(vm, target, 0);
var ret = qbdi.getGPR(vm, qbdi.REG_RETURN);
qbdi.unregisterTraceCallbacks(vm);
qbdi.destroyVM(vm);
```

范围管理：`addInstrumentedRange()`、`removeInstrumentedRange()`、`removeAllInstrumentedRanges()`。执行入口：`call()` / `run()`。寄存器：`getGPR()` / `setGPR()`，常量包括 `REG_RETURN`、`REG_SP`、`REG_LR`、`REG_PC`。错误信息通过 `qbdi.lastError()` 获取。默认 trace 输出为 `/data/data/<package>/trace_bundle.pb`。

## 9. 易错点

1. Native attach 自动执行原函数；replace 型 hook 只有显式 `$orig()` 才执行原函数。
2. Java 字段用 `.value`，Java 原方法用 `this.$orig(...)`。
3. Spawn 模式下 Java API 放在 `Java.ready()` 内。
4. `Java.choose` 的 wrapper 不应带出 `onMatch` 生命周期。
5. `CModule` 在 hook 存活期间必须保留引用。
6. `callNative()` 只适合少量整数/指针参数；复杂签名使用 `NativeFunction`。
7. 修改代码后调用 `Memory.flushCodeCache()`。
8. 高频路径优先 DSL 或 CModule，避免每次命中都进入 JS runtime。
