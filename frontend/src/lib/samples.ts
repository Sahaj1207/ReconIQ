export interface Sample {
  id: string;
  label: string;
  description: string;
  text: string;
}

export const SAMPLES: Sample[] = [
  {
    id: "phishing",
    label: "Phishing email",
    description: "Defanged credential-harvesting lure",
    text: `From: "Secure Bank Support" <support[at]secure-bank-verify[dot]com>
Subject: Urgent: Your account has been suspended

Dear customer,

We detected unusual sign-in activity on your account. To avoid permanent
suspension, verify your identity within 24 hours:

  hxxps://secure-bank-verify[.]com/login?session=8f2a91

If you cannot access the link, call our fraud desk at +1-800-555-0199.

Sent from 185.220.101.47`,
  },
  {
    id: "soc-alert",
    label: "SOC alert",
    description: "EDR beaconing alert with C2 infrastructure",
    text: `[ALERT] EDR-4471 | Severity: High | Host: FIN-WS-022
Process powershell.exe established outbound connections to:
  - 45.33.32.156:443
  - 2a03:2880:f12f:83:face:b00c::25de
  - update-cdn[.]net
Downloaded payload from hxxp://update-cdn[.]net/a/stage2.bin
Analyst contact: soc-oncall@example.org`,
  },
  {
    id: "benign",
    label: "Benign note",
    description: "Internal message with private addresses only",
    text: `Hi team, the staging server moved to 10.0.4.12 and the wiki is now at
https://wiki.example.com/onboarding. Ping me at alex@example.com if anything breaks.`,
  },
];
