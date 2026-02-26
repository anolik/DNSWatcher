export type CheckStatus = 'pass' | 'warn' | 'fail';

export interface StatusRowData {
  label: string;
  value: string;
  status: CheckStatus;
  detail: string;
}

export interface StepData {
  index: string;
  label: string;
  state: 'complete' | 'current' | 'upcoming';
}

export interface DomainCheckData {
  domain: string;
  statusSummaryLine1: string;
  statusSummaryLine2: string;
  rows: StatusRowData[];
  lastChecked: string;
  nextRun: string;
  drift: string;
  envBadge: string;
}
