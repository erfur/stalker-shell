import { log } from "./logger";
import { TracerAgent } from "./stalker";
import { InterceptorAgent } from "./interceptor";

let tracer = new TracerAgent();
let interceptor = new InterceptorAgent();

rpc.exports = {

    logaddr(addr: string) {
        interceptor.logAddr(addr);
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