import { log } from "./logger";

export class Patches {
    moduleName: string;

    constructor(moduleName: string) {
        this.moduleName = moduleName;
    }

    fixedJmp (addr: NativePointer, target: NativePointer) {
        const instr = Instruction.parse(addr);
        log.info(`patching instruction at ${addr}: ${instr}`);

        Memory.patchCode(addr, 0x10, code => {
            const cw = new X86Writer(code, { pc: addr });
            cw.putJmpAddress(target);
        });
    }

    modifyPurchasedFlag() {
        let addr = Process.getModuleByName(this.moduleName).base.add(ptr(0x41871f));
        Interceptor.attach(addr, {
            onEnter: function (args) {
                let ctx = this.context as X64CpuContext;
                ctx.rcx = ptr(0);
            }
        })
    }

    dumpJson() {
        Interceptor.attach(Process.getModuleByName(this.moduleName).base.add(ptr(0x9c686)), {
            onEnter: function (args) {
                let ctx = this.context as X64CpuContext;
                let jsonStrLen = ctx.r14.add(4).readU32();
                let jsonStr = ctx.r14.add(0x10).readPointer().readUtf16String(jsonStrLen);
                log.info(`recv json: ${jsonStr}`);

                // let obj = JSON.parse(jsonStr ? jsonStr : "");

                // if (obj["purchaseStatus"] && obj["purchaseStatus"] == "NotPurchased") {
                //     let newJsonStr = JSON.stringify({purchaseStatus: "Succeeded"});

                //     log.info(`replacing with json ${newJsonStr}`);

                //     ctx.r14.add(4).writeU32(newJsonStr.length);
                //     ctx.r14.add(0x10).readPointer().writeUtf16String(newJsonStr);
                // }
            }
        });

        let jsonPtr: NativePointer;

        Interceptor.attach(Process.getModuleByName(this.moduleName).base.add(ptr(0x90314)), {
            onEnter: function (args) {
                let ctx = this.context as X64CpuContext;
                jsonPtr = ptr(ctx.rdx.toString());
                // let jsonStrLen = ctx.rdx.add(4).readU32();
                // let jsonStr = ctx.rdx.add(0x10).readPointer().readUtf16String(jsonStrLen);
                // log.info(`json: ${jsonStr}`);

                // let obj = JSON.parse(jsonStr ? jsonStr : "");

                // if (obj["purchaseStatus"] && obj["purchaseStatus"] == "NotPurchased") {
                //     let newJsonStr = JSON.stringify({purchaseStatus: "Succeeded"});

                //     log.info(`replacing with json ${newJsonStr}`);

                //     ctx.r14.add(4).writeU32(newJsonStr.length);
                //     ctx.r14.add(0x10).readPointer().writeUtf16String(newJsonStr);
                // }
            },
            onLeave: function (ret) {
                // let ctx = this.context as X64CpuContext;

                // log.info(`json ptr: ${hexdump(jsonPtr.readPointer(), {length: 0x40})}`);

                let jsonStrLen = jsonPtr.readPointer().add(4).readU32();
                let jsonStr = jsonPtr.readPointer().add(0x10).readPointer().readUtf16String(jsonStrLen);
                log.info(`json: ${jsonStr}`);

                let obj = JSON.parse(jsonStr ? jsonStr : "");

                if (obj["purchaseStatus"] && obj["purchaseStatus"] == "NotPurchased") {
                    let newJsonStr = JSON.stringify({purchaseStatus: "Succeeded"});

                    log.info(`replacing with json ${newJsonStr}`);

                    jsonPtr.readPointer().add(4).writeU32(newJsonStr.length);
                    jsonPtr.readPointer().add(0x10).readPointer().writeUtf16String(newJsonStr);
                }
            }
        });
    }
}
