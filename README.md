# Security Header Scanner

A Python tool that audits websites for missing HTTP security headers based on OWASP practices.

## What It Does

- Scans a single user given site
- Scans 5 sites from a list (Google, Facebook, GitHub, Reddit, Bank of America)
- Checks for 6 critical security headers
- Scores each site out of 6
- Assigns a risk level — HIGH, MEDIUM, or LOW
- Exports a timestamped CSV report
- Color coded terminal output

## Headers Checked

| Header | Purpose |
|---|---|
| Content-Security-Policy | Prevents XSS attacks |
| X-Frame-Options | Prevents clickjacking |
| Strict-Transport-Security | Forces HTTPS connection |
| X-Content-Type-Options | Prevents MIME sniffing |
| Referrer-Policy | Controls info leakage |
| Permissions-Policy | Limits browser features |

## How To Run It

Install the required library —
```
pip install requests
```

Run the scanner —
```
python scanner.py
```

Choose option 1 to scan a single site or option 2 to scan all sites in sites.txt

## Example Output
```
scanning: https://github.com
--------------------------------------------------
  FOUND    Strict-Transport-Security
  MISSING  Content-Security-Policy
  MISSING  X-Frame-Options

  Security Score: 3/6
  Risk Level: MEDIUM
```

## Notes

Some sites assumed to be secure like Bank of America score low on this scan. This does not mean they are insecure — large organizations typically have dedicated security teams and infrastructure that goes much deeper than response headers. This tool audits publicly visible security hygiene only.

## Skills Demonstrated

- Python scripting
- HTTP requests and response handling
- OWASP security standards
- Automated reporting and CSV export
- File handling
