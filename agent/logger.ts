class Logger {
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