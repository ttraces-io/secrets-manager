# Security Research & Vulnerability Bounties Directory

> **Automated AI Bot Tracker**: Continuously discovering, parsing, standardizing, and publishing active Bug Bounty & Vulnerability Disclosure Programs (VDPs) across the global security landscape.

---

## 📊 Summary Metrics

| Metric | Value |
| :--- | :--- |
| **Total Tracked Programs** | **15** |
| **Paid Bug Bounties** | **10** |
| **Vulnerability Disclosure Programs (VDPs)** | **5** |
| **Combined Max Bounty Pool** | **$2,850,000.00** |
| **Last Bot Sync** | `2026-09-21 00:21:05 UTC` |

---

## 🛡️ Active Bug Bounty Programs

| Program Name | Platform | Max Reward | Scope Summary | Policy / Scope Link | Tags | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Apple Security Bounty** | Direct / Self-Hosted | $2,000,000 | iOS, macOS (+3 more) | [View Policy](https://security.apple.com/bounty/) | `OS` `Hardware` `Mobile` | 🟢 Active |
| **Microsoft Security Response Center** | Direct / Self-Hosted | $250,000 | Azure, Hyper-V (+3 more) | [View Policy](https://www.microsoft.com/en-us/msrc/bounty) | `Cloud` `OS` `Enterprise` | 🟢 Active |
| **Ethereum Foundation Bug Bounty** | Immunefi | $250,000 | Execution Specs, Consensus Specs (+2 more) | [View Policy](https://bounty.ethereum.org/) | `Web3` `Blockchain` `Smart Contracts` | 🟢 Active |
| **Google Vulnerability Reward Program** | Direct / Self-Hosted | $150,000 | *.google.com, *.android.com (+2 more) | [View Policy](https://bughunters.google.com/about/rules) | `Cloud` `Mobile` `Web` | 🟢 Active |
| **Meta Bug Bounty Program** | Direct / Self-Hosted | $130,000 | Facebook, Instagram (+2 more) | [View Policy](https://www.facebook.com/whitehat/info) | `Social` `Mobile` `VR` | 🟢 Active |
| **GitHub Bug Bounty** | HackerOne | $30,000 | github.com, GitHub Enterprise (+2 more) | [View Policy](https://bounty.github.com/) | `Web` `Developer Tools` `Cloud` | 🟢 Active |
| **d-you App & German EUDI Wallet Ecosystem (HackerOne)** | HackerOne | $10,000 | *.common_codes.com | [View Policy](https://hackerone.com/common_codes) | `Web` `HackerOne` | 🟢 Active |
| **Wolt (HackerOne)** | HackerOne | $10,000 | *.wolt.com | [View Policy](https://hackerone.com/wolt) | `Web` `HackerOne` | 🟢 Active |
| **Agoda Public (HackerOne)** | HackerOne | $10,000 | *.agoda-public.com | [View Policy](https://hackerone.com/agoda-public) | `Web` `HackerOne` | 🟢 Active |
| **Coupang Taiwan (HackerOne)** | HackerOne | $10,000 | *.coupang_tw.com | [View Policy](https://hackerone.com/coupang_tw) | `Web` `HackerOne` | 🟢 Active |
| **CISA Vulnerability Disclosure Policy** | Direct / Self-Hosted | VDP (Unpaid) | *.cisa.gov, Federal Executive Branch Systems | [View Policy](https://www.cisa.gov/vulnerability-disclosure-policy) | `Government` `VDP` `Infrastructure` | 🟢 Active |
| **Cloudflare Security Disclosure (security.txt)** | Direct / Self-Hosted | VDP (Unpaid) | *.cloudflare.com | [View Policy](https://www.cloudflare.com/disclosure/) | `Self-Hosted` `RFC 9116` `Web` | 🟢 Active |
| **Stripe Security Disclosure (security.txt)** | Direct / Self-Hosted | VDP (Unpaid) | *.stripe.com | [View Policy](https://hackerone.com/stripe#overview) | `Self-Hosted` `RFC 9116` `Web` | 🟢 Active |
| **Airbnb Security Disclosure (security.txt)** | Direct / Self-Hosted | VDP (Unpaid) | *.airbnb.com | [View Policy](https://hackerone.com/airbnb#overview) | `Self-Hosted` `RFC 9116` `Web` | 🟢 Active |
| **Gitlab Security Disclosure (security.txt)** | Direct / Self-Hosted | VDP (Unpaid) | *.gitlab.com | [View Policy](https://hackerone.com/gitlab/) | `Self-Hosted` `RFC 9116` `Web` | 🟢 Active |

---

## 🌐 Dataset Access & Integration

The complete dataset is automatically exported in structured formats for integration into your security pipelines, scanners, or research workflows:

- 📄 **Master JSON**: [`data/bounties.json`](data/bounties.json)
- ⚡ **Minified JSON**: [`data/bounties.min.json`](data/bounties.min.json)
- 📂 **By Platform**:
  - [HackerOne Programs](data/by-platform/hackerone.json)
  - [Bugcrowd Programs](data/by-platform/bugcrowd.json)
  - [Immunefi Web3 Programs](data/by-platform/immunefi.json)
  - [Direct / Self-Hosted VDPs](data/by-platform/self_hosted.json)

---

## 🤖 Dynamic Discovery Pipeline Process

1. **Known Platform Crawling**: Regularly syncs public endpoints from HackerOne, Bugcrowd, Immunefi, Intigriti, and community lists.
2. **RFC 9116 security.txt Scanner**: Scans top internet domains for `/.well-known/security.txt` specifications.
3. **AI Search & Feed Agent**: Monitors security news, RSS announcements, and social feeds for newly announced programs.
4. **Gemini Policy Parser**: Extracts scope rules, safe harbor clauses, and payment tiers from unstructured VDP pages into standard schemas.
5. **Continuous Verification**: Dead links and unmaintained programs are automatically flagged and deprecated.

---

*Automated by [Bounty Bot](src/main.py)*
