Optional offline geolocation for the login map.

Put ONE MaxMind-format city database (.mmdb) in this folder and reload Crumbs:

  - DB-IP "IP to City Lite"  : free, no account, CC BY 4.0
                               https://db-ip.com/db/download/ip-to-city-lite   (choose the MMDB download)
  - MaxMind GeoLite2-City    : free account at maxmind.com

Crumbs reads it with its own small reader (no extra Python package) and never sends addresses anywhere.
Without a database, the map uses locations already returned by your Shodan / AbuseIPDB / VirusTotal lookups.
