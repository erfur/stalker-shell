import { NONAME } from "dns";
import { FormatInputPathObject } from "path";
import { log } from "./logger";

export class TracerAgent {
    data: { [tid: number] : Array<ArrayBuffer>} = {};
    targetModule: string;
    stalkedTids: Array<ThreadDetails> = new Array();

    constructor() {
        // find out how to find the main module name
        this.targetModule = "alacritty";
    }

    /**
     * To be called when tracing will begin.
     */
    filterModules() {
        new ModuleMap((m: Module) => {
            if (m.name != this.targetModule) {
                Stalker.exclude(m);
            }

            return false;
        });
    }

    /** 
     * Somehow this doesnt work for calls.
     */
    filterEverything() {
        let module = Process.getModuleByName(this.targetModule);
        Stalker.exclude({
            base: ptr(0),
            size: new UInt64(module.base.toString()).toNumber(),
        });
        Stalker.exclude({
            base: module.base.add(module.size),
            size: 2**64-1-(new UInt64(module.base.add(module.size).toString()).toNumber()),
        })
    }

    checkRange(addr: NativePointer) {
        let begin = Process.getModuleByName(this.targetModule).base;
        let end = begin.add(ptr(Process.getModuleByName(this.targetModule).size));
        return addr >= begin && addr < end;
    }

    /**
     * Start tracing.
     */
    activate(thread_no: number = 0) {
        // log.info(`stalking thread ${thread_no}`);
        // this.filterEverything();
        Process.enumerateThreads().map((tid) => {
            this.data[tid.id] = new Array<ArrayBuffer>();
            this.stalkedTids.push(tid);
            log.info(`stalking thread ${tid.id}`)
            Stalker.follow(tid.id, {
                events: {
                    call: true,
                    // ret: false,
                },
                onReceive: (events) => {
                    this.data[tid.id].push(events);
                }
            });

        })
    }

    /**
     * Start timed tracing with delay.
     * @param delay The delay tracing should start after now in ms.
     * @param interval The time tracing should take in ms.
     */
    activateTimed(delay: any, interval: any) {
        setTimeout(() => {
            log.info("initiating stalker.");
            this.activate();

            setTimeout(() => {
                log.info("stopping stalker.");
                this.deactivate();
            }, interval);
        }, delay);
    }

    activateAtAddr(addr: number | string, module: string = "") {
        let targetAddr = ptr(addr);

        if (module) {
            let moduleBase = Process.getModuleByName(module).base;
            targetAddr = targetAddr.add(moduleBase);
        }

        log.info(`attaching interceptor at addr ${targetAddr}`);

        Interceptor.attach(targetAddr, {
            onEnter: function (args) {
                log.info(`thread ${this.threadId} hit addr ${targetAddr}`)
                Stalker.follow(this.threadId, {
                    events: {
                        call: true,
                        // ret: false,
                    },
                    onReceive: (events) => {
                        this.data[this.threadId].push(events);
                    }
                });
            },
            onLeave: function (ret) {
                log.info(`thread ${this.threadId} leaving addr ${targetAddr}`)
                // Interceptor.revert(targetAddr);
                Stalker.unfollow(this.threadId);
            }
        })
    }

    /**
     * Stop tracing.
     */
    deactivate(thread_no: number = 0) {
        // log.info(`unstalking thread ${thread_no}`);
        this.stalkedTids.map((tid) => {
            log.info(`unstalking thread ${tid.id}`)
            Stalker.unfollow(tid.id);
        })
    }

    reset() {
        this.data = {};
        this.stalkedTids = new Array();
    }

    /**
     * Parse events and return in json.
     * 
     * ```
     * type StalkerCallEventFull = [ "call", NativePointer | string, NativePointer | string, StalkerCallProbeId ];
     * type StalkerCallEventBare = [         NativePointer | string, NativePointer | string, StalkerCallProbeId ];
     * ```
     */
    parseData() {
        return Object.entries(this.data).map(([tid, arr]) => {
            return [
                tid,
                arr.map((events) => {
                    return Stalker.parse(events, {
                        stringify: false,
                        annotate: false,
                    });
                }),  
            ];
        });
    }
}