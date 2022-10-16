import { log } from "./logger";
import { TracerAgent } from "./stalker";
import { InterceptorAgent } from "./interceptor";
import { Patches } from "./patch";

let tracer = new TracerAgent();
let interceptor = new InterceptorAgent();
// let patches = new Patches();

rpc.exports = {

    // decommissioned for now
    // logaddr(addr: string) {
    //     interceptor.logAddr(ptr(addr));
    // },

    debug() {
        log.toggleDebug();
    },

    logmodule(addrjson: string) {
        interceptor.logModule(JSON.parse(addrjson));
    },

    moduleresults() {
        return interceptor.stats.stats;
    },

    maps() {
        return Process.enumerateModules();
    },

    threads() {
        return Process.enumerateThreads();
    },

    stalkinterval (delay, interval) {
        tracer.activateTimed(delay*1000, interval*1000);
    },

    stalkaddr (addr: number | string, module?: string) {
        tracer.activateAtAddr(addr, module)
    },

    stalk(thread_no: number) {
        tracer.activate(thread_no);
    },

    unstalk(thread_no: number) {
        tracer.deactivate(thread_no);
    },

    results() {
        return tracer.parseData();
    },

    reset() {
        tracer.reset()
    }
}