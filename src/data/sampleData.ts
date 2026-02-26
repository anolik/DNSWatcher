import type { DomainCheckData, StepData } from '../types';

export const sampleDomain: DomainCheckData = {
  domain: 'mail.mica.example',
  statusSummaryLine1: 'All checks',
  statusSummaryLine2: 'passing',
  rows: [
    {
      label: 'SPF',
      value: 'PASS',
      status: 'pass',
      detail: 'Includes authorized senders; no permerror',
    },
    {
      label: 'DKIM',
      value: 'PASS',
      status: 'pass',
      detail: 'Selector(s) found: s1, s2',
    },
    {
      label: 'DMARC',
      value: 'PASS',
      status: 'pass',
      detail: 'Policy: quarantine; alignment OK',
    },
  ],
  lastChecked: 'Today 10:48',
  nextRun: 'In 24h',
  drift: 'None',
  envBadge: 'PROD',
};

export const stepperData: StepData[] = [
  { index: '01', label: 'Add domains', state: 'complete' },
  { index: '02', label: 'Set expectations', state: 'complete' },
  { index: '03', label: 'Monitor checks', state: 'current' },
  { index: '04', label: 'Alert & respond', state: 'upcoming' },
];

export const previewTabs = ['DOMAINS', 'CHECKS', 'ALERTS', 'SETTINGS'] as const;
