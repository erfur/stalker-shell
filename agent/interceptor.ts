import { log } from "./logger";

interface ModuleOffsets {
    name: string;
    functions: Array<FunctionInfo>;
}

interface FunctionInfo {
    name: string;
    offset: number;
} 

export class InterceptorAgent {
    logAddr(addr: NativePointer, name: string = "") {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                log.info(`fcn ${name} @${addr}, ret ${this.returnAddress}, tid ${this.threadId}`)
            },
            onLeave: function (ret) {
                log.info(`fcn ${name} @${addr} return`);
            }
        })
    }

    logModule(moduleInfo: ModuleOffsets) {
        let moduleName = moduleInfo.name;
        let moduleBase = Process.getModuleByName(moduleName).base;
        log.info(`module ${moduleName}, base ${moduleBase}`);

        moduleInfo.functions.map((fcnInfo) => {
            this.logAddr(moduleBase.add(fcnInfo.offset), fcnInfo.name);
        })
    }
}