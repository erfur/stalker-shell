import { log } from "./logger";

export class InterceptorAgent {
    logAddr(addr: string) {
        Interceptor.attach(ptr(addr), {
            onEnter: function (args) {
                log.info(`thread ${this.threadId} hit addr ${ptr(addr)}`)
            },
            onLeave: function (ret) {
                log.info(`thread ${this.threadId} leaving addr ${ptr(addr)}`)
            }
        })
    }
}