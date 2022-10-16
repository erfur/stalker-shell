import { log } from "./logger";

interface ModuleOffsets {
    name: string;
    functions: Array<FunctionInfo>;
}

interface FunctionInfo {
    name: string;
    offset: number;
}

interface FunctionTraceInfo {
    type: string;
    fcnOffset: NativePointer;
    retModuleName?: string;
    retOffset?: NativePointer;
    retValue?: NativePointer;
}

class FunctionStats {
    stats: { [tid: number] : Array<FunctionTraceInfo> } = {};

    constructor() {
    }

    add(tid: number, info: FunctionTraceInfo) {
        if (!this.stats[tid]) {
            this.stats[tid] = new Array();
        }

        this.stats[tid].push(info);
    }

    get(tid: number) {
        return this.stats[tid];
    }
}

export class InterceptorAgent {
    stats = new FunctionStats();

    // TODO module should be optional
    logAddr(addr: NativePointer, fcnName: string, module: Module) {
        let stats = this.stats;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                let tid = this.threadId;
                let type = "call";
                let fcnOffset = addr.sub(module.base);

                let retModule = Process.getModuleByAddress(this.returnAddress);
                let retOffset = this.returnAddress.sub(retModule.base);
                let retModuleName = retModule.name;

                log.debug(`fcn ${type}: @${fcnOffset}, ret ${retModuleName}+${retOffset}, tid ${tid}`);
                
                // naming is important
                stats.add(tid, {type, fcnOffset, retModuleName, retOffset});
            },
            onLeave: function (ret) {
                let tid = this.threadId;
                let type = "ret";
                let fcnOffset = addr.sub(module.base);

                log.debug(`fcn ${type}: @${fcnOffset}, tid ${tid}`);
                stats.add(tid, {type, fcnOffset, retValue: ret});
            }
        })
    }

    logModule(moduleInfo: ModuleOffsets) {
        let moduleName = moduleInfo.name;
        let module = Process.getModuleByName(moduleName);
        let moduleBase = module.base;
        log.info(`module ${moduleName}, base ${moduleBase}`);

        moduleInfo.functions.map((fcnInfo) => {
            this.logAddr(moduleBase.add(fcnInfo.offset), fcnInfo.name, module);
        })
    }
}