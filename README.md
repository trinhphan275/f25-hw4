## Recursive DNS Resolver — Implementation Guide

This repository contains a recursive DNS resolver implemented in `resolve.py`. It performs full recursion itself (no RD/recursive queries), starting from the root servers, following referrals, handling CNAME restarts, unglued name servers, and printing results similar to the `host` utility for A, AAAA, and MX records.

The resolver includes robust error handling and both exact-result and intermediate delegation caching to minimize repeated network queries across runs in the same process.

### Quick start

Prerequisite: Python 3 and dnspython.

Install dependency (one of):

```
pip3 install dnspython
pip install dnspython
python -m pip install dnspython
```

Run lookups:

```
python resolve.py yahoo.com
python resolve.py uic.edu uic.edu   # demonstrates exact-result caching
python resolve.py illinois.edu uic.edu -v  # demonstrates intermediate (edu.) caching and timing
python resolve.py www.internic.net  # CNAME restart scenario
```

Output format matches `host` style, for example:

```
uic.edu. has address 128.248.155.93
uic.edu. mail is handled by 10 uic-edu.mail.protection.outlook.com.
```

### How it works

Key components in `resolve.py`:

- ROOT_SERVERS: A list of IPv4 root server addresses used as the starting point.
- CACHE: Exact-answer cache keyed by (dns.name.Name, rdatatype) to avoid identical network queries.
- DELEGATION_CACHE: Intermediate cache that maps a zone name (e.g., `edu.`) to a list of IPv4 nameserver IPs for faster subsequent lookups within that zone.
- RESOLVING: A guard set to prevent infinite loops during unglued nameserver resolution.
- collect_results(name): Orchestrates fetching A, then AAAA, then MX; accumulates full CNAME chains for A lookups.
- lookup(target, qtype): High-level loop that follows CNAME restarts and builds a final answer message, using the best known delegation (from DELEGATION_CACHE) or the root servers to start.
- _lookup_recursive(target, qtype, nameservers): The recursive engine. It queries nameservers, handles referrals, resolves unglued NS A records when needed, caches delegations, and returns responses.

### Resolution strategy

1) Start at the closest known delegation for the target name. If none exist, start at the root servers.
2) For each server in the provided list (IPv4 only), perform a UDP query with a 3-second timeout.
3) If the response has:
   - Final answers (answer section): cache and return.
   - NXDOMAIN or an SOA in the authority section with no answers (NODATA): treat as a final negative, cache and return.
   - Referral (NS in authority):
     - If glue A records are in Additional: cache those server IPs for the delegated zone and continue recursion with them.
     - If no glue: resolve NS hostnames to A records by recursively querying from roots; collect a few IPv4 addresses (limit 3) to continue, cache them for the zone, and recurse.
4) If a server times out or errors, move on; do not retry the same server.
5) Exhaustively try all servers in a referral set (once each) before giving up on that step.

### Error handling (per assignment spec)

- 3-second timeout for all queries.
- Only IPv4 is used for querying nameservers (AAAA records may be printed for target results, but resolver-to-authority communication is IPv4-only).
- Exhaustively try all available nameservers in a referral (each at most once).
- No exceptions escape to the user; if a domain cannot be resolved, the script prints nothing or partial results without crashing.

### Caching

- Exact-result cache (CACHE): Responses for the exact (name, type) are reused within the same process.
- Intermediate delegation cache (DELEGATION_CACHE): The resolver stores IPv4 nameserver IPs for zones (e.g., `edu.`). Subsequent queries under the same zone start from these servers, reducing queries (e.g., resolving `illinois.edu` then `uic.edu` queries `edu` only once).
- Note: Caches are in-memory and do not persist across executions; TTL-based expiration is not implemented (not required by the assignment).

### CNAME restarts

- The resolver collects the full CNAME chain and restarts querying for the new target as needed, up to a safe limit to prevent infinite loops.
- When referrals return no Additional (glue), it resolves NS names to A records, gathers a few IPv4 addresses quickly, and continues recursion—keeping the run under the allotted time budget.
- Negative responses (NXDOMAIN/NODATA with SOA) are treated as final to avoid wasting time on fruitless retries.

### Unglued nameservers

- When the referral provides NS names without glue, the resolver recursively resolves those NS hostnames (from roots) to obtain A records, caches them for that zone, and proceeds.
- A small guard set (RESOLVING) prevents infinite recursion when NS hostnames are within the same zone being resolved.

### Verbose timing

Use `-v` to see per-domain and total execution times. This is helpful to observe the effect of caching between successive lookups in one run.

---

## Homework 4: Recursive DNS Resolver

Your goal is to recreate the functionality of a recursive DNS resolver.
Your program will not be allowed to perform any recursive queries (i.e.
request that another server perform recursion for it); it must perform all
recursion itself.


### Getting Setup

Most of what you'll need in this assignment is included in the `resolve.py`
skeleton file included in this repo. You'll need to install
the [dnspython](http://www.dnspython.org/) library though.  You can do so
using [pip](https://pip.pypa.io/en/stable/).  In most cases you can
do so by running one of the following commands on your system:

 * `pip3 install dnspython`
 * `pip install dnspython`
 * `python -m pip install dnspython`

You're responsible for getting `dnspython` installed on your system.  If you
have any problems getting the library installed, please ask on Piazza.


### The Assignment

You'll find a `resolve.py` file in your repo.  This file contains
code that approximates the functionality of the `host` program.  The program
takes a domain name, and returns a summary of DNS information about the domain.
For example, given the domain "yahoo.com", `host` returns the "A", "AAAA"
and "MX" records for the domain.  You can test this out by running
the `resolve.py` command as so: `python resolve.py yahoo.com`.

You can lookup multiple domains in the same execution by passing multiple
domains to the program (e.g. `python resolve.py first.com second.edu third.org`).

`resolve.py` currently queries a DNS server (`8.8.8.8`) to find information
about domains.  That DNS server handles the recursive part of DNS for you
(i.e. `8.8.8.8` by default doesn't know where to find `yahoo.com`, so it
asks a root server, and the root server tells `8.8.8.8` where to find
information about `.com`, so then `8.8.8.8` asks the new server where to
find `yahoo.com`, etc.)

Your task in this assignment is to implement this recursive functionality
on your own.  When your version of `resolve.py` is run, it will not
query `8.8.8.8` (or any other recursive resolver).  Your `resolve.py` will
query a root server itself, as well as performing any further needed
queries.

The IP addresses of the root servers are hard coded into the `resolve.py`
in the global `ROOT_SERVERS` list. Your program should start by querying one
of these servers. **A very good first step** in your solution will be
to find where `8.8.8.8` is in the code currently, and make sure you instead
query one of the root servers.


### Handling Errors

Your code should be able to handle cases where DNS servers are down or slow
to respond. The
[rules governing DNS and how to handle errors](https://tools.ietf.org/html/rfc1034)
are very complex.  For the purposes of this assignment, we'll be using a
simplified set of rules for handling errors.

 * Use a timeout value of 3 seconds for all queries.  Any request taking
   more than 3 seconds to respond should be treated as non-responsive.
 * You should exhaustively try all available servers when trying to answer
   a query.  For example, if a request to a root server gives you
   13 servers for the ".com" zone, you should try each of those 13 servers
   before giving up.
 * If you receive an error or non-response from a server, you should not
   retry the server.  Only query each server once.
 * Only query servers over IPv4.  You should not query servers over IPv6 when
   trying to resolve domains.

Your code should never throw an exception.  Dumping a stacktrace is not
an appropriate response for any query.  If you are unable to get a result
for a domain, your code should not print nothing out.

If you have any questions regarding how to handle errors and non-responsive
servers, please ask on Piazza.


### Grading

 * **15 points each**: Perform A record lookups without querying a recursive
   nameserver (two tests, for a total of 30 possible points).
 * **10 points**: Perform lookups in the case of CNAME restarts (e.g.
   `www.internic.net`).  **Note** that your code should run successfully even
   when the CNAME returns no "Additional" section.
 * **10 points**: Perform lookups of "unglued" nameservers (e.g.
   `www.yahoo.com.tw`)
 * **20 points**: Correctly handle errors, so that your code correctly
   deals with non-responsive or slow servers.
 * **15 points**: Implement a caching system, so that exact duplicate lookups for
   the same domain do not result in additional queries.  (e.g. running
   `python resolve.py uic.edu uic.edu`, sould result in the same number of
   queries as running `python resolve.py uic.edu`).
 * **15 points**: Implement a more sophisticated caching system, that caches
   intermediate results too.  (e.g. if you run
   `python resolve.py uic.edu illinois.edu`, you sould only query for `edu`
   once).

### Helpful Links
 * [TCP IP Guide](http://www.tcpipguide.com/free/t_TCPIPDomainNameSystemDNS.htm)
 * [IANA DNS Parameters](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
