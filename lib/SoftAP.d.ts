declare var SoftAPOptions: any;
export { SoftAPOptions };
export declare class SoftAP {
    __publicKey: any;
    keepAlive: boolean;
    noDelay: boolean;
    timeout: number;
    host: string;
    port: number;
    warmedUp: boolean;
    protocol: string;
    constructor(options: any);
    _sendProtocolCommand(cmd: any, cb: Function): void;
    _sendProtocolCommandTcp(cmd: any, cb: Function): void;
    _sendProtocolCommandHttp(cmd: any, cb: Function): void;
    __sendCommand(cmd: any, cb: Function): void;
    scan(cb: Function): void;
    connect(index: any, cb?: any): void;
    deviceInfo(cb: Function): void;
    publicKey(cb: Function): void;
    set(data: any, cb: Function): void;
    setClaimCode(code: string, cb: Function): void;
    aesEncrypt(data: any, kiv?: any): {
        kiv: any;
        encrypted: any;
    };
    configure(opts: any, cb: Function): void;
    version(cb: Function): void;
    securityValue(name: string): any;
    securityLookup(dec: string): any;
    eapTypeValue(name: string): any;
}
