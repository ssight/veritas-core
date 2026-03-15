export interface PkInfo {
    id: string;
    authority: string;
    device_model: string;
    issued: number;
}

export interface SigInfo {
    cert_id: string;
}

export function keyread(keypath: string): PkInfo;
export function siginfo(path: string): SigInfo;
export function sign(imgpath: string, key_id: string, newpath: string): undefined;
export function verify(imgpath: string, keypath: string): boolean;
