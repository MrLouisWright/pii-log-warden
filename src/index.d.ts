import type { Report, Rule } from './core.js';
export * from './core.js';
export interface PiiOptions {
  allFiles?: boolean; exclude?: string[]; privateIps?: boolean; ignoreEmailDomains?: string[]; maxPerFile?: number;
  /** Redact matches (in place, or into redactDir). */
  redact?: boolean; redactDir?: string; style?: 'placeholder' | 'mask';
  /** Scan this text instead of files. */
  stdinText?: string; stdinName?: string; onRedacted?: (text: string) => void;
  rules?: string[]; now?: Date; toolVersion?: string;
}
export interface Hit { rule: string; line: number; column: number; value: string; masked: string }
export declare const RULES: Record<string, Rule>;
export declare function check(paths: string[], opts?: PiiOptions, config?: Record<string, unknown>, configFile?: string): Report;
export declare function scanText(text: string, opts?: PiiOptions): Hit[];
export declare function redactText(text: string, opts?: PiiOptions): { text: string; count: number };
export declare function listFiles(paths: string[], opts?: { all?: boolean; exclude?: string[] }): string[];
export declare function luhn(digits: string): boolean;
export declare function ibanValid(iban: string): boolean;
export declare function mask(rule: string, value: string): string;
