class Logger {
    isDebug: boolean = false;

    toggleDebug() {
        this.isDebug = !this.isDebug;
    }

    debug(message: string): void {
        if (this.isDebug) {
            this.info(message);
        }
    }

    info(message: string): void {
        send({
            type: "info",
            payload: message,
        })
    }

    error(message: string) {
        send({
            type: "error",
            payload: message,
        })
    }

    data(blob: any) {
        send({
            type: "blob",
        }, blob)
    }

    json(data: any) {
        send({
            type: "json",
            payload: data,
        })
    }
}

export const log = new Logger();