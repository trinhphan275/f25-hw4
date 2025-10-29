"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse
import time

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 25 October 2018
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

# A global cache to store responses.
# The key will be a tuple: (dns.name.Name, dns.rdatatype)
# The value will be the dns.message.Message response.
CACHE = {}

# Track what we're currently resolving to prevent infinite loops
RESOLVING = set()

# Cache for delegations (intermediate results): map zone name -> list of IPv4 NS IPs
# Example: dns.name.from_text('edu.') -> ['192.5.6.30', ...]
DELEGATION_CACHE = {}

def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    
    # lookup A - this will follow CNAMEs and return the full chain
    response = lookup(target_name, dns.rdatatype.A)
    
    # Collect ALL CNAMEs from the answer (the full CNAME chain)
    cnames = []
    current_name = name
    arecords = []
    
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            # This is a CNAME record
            for answer in rrset:
                cnames.append({"name": str(answer), "alias": current_name})
                current_name = str(answer)
        elif rrset.rdtype == 1:  # A record
            a_name = rrset.name
            for answer in rrset:
                arecords.append({"name": a_name, "address": str(answer)})
    
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response

def _lookup_recursive(target_name: dns.name.Name, qtype: int, nameservers: list) -> dns.message.Message:
    """
    A helper function that recursively queries nameservers.
    It exhaustively tries all servers in the `nameservers` list.
    """
    global CACHE, RESOLVING
    
    # Check cache first for this exact query
    cache_key = (target_name, qtype)
    if cache_key in CACHE:
        return CACHE[cache_key]
    
    query = dns.message.make_query(target_name, qtype)

    # Iterate through all provided servers exhaustively
    for _, server_ip in enumerate(dict.fromkeys(nameservers)):
        # Ensure we only try IPv4 literals (skip anything else just in case)
        if ':' in server_ip:
            continue
        
        try:
            # Use a 3-second timeout as required
            response = dns.query.udp(query, server_ip, timeout=3.0)

            # Case 1: We got a final positive answer. Cache it and return.
            if response.answer:
                CACHE[cache_key] = response
                return response

            # Case 1b: Negative response (NXDOMAIN or NODATA indicated by SOA)
            if response.rcode() != dns.rcode.NOERROR:
                CACHE[cache_key] = response
                return response

            # NODATA typically includes an SOA in authority, treat as final
            has_soa = any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority)
            if has_soa:
                CACHE[cache_key] = response
                return response

            # Case 2: We got a referral.
            if response.authority:
                # Get the names of the next-level servers from the authority section.
                ns_names = []
                zone_name = None
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NS:
                        # This rrset.name is the zone being delegated (e.g., 'edu.')
                        zone_name = rrset.name
                        for rr in rrset:
                            ns_names.append(str(rr.target).rstrip('.'))

                if not ns_names:
                    # No NS in authority and no answer: nothing further to do
                    CACHE[cache_key] = response
                    return response

                # Get the IPs (glue) for these servers from the additional section.
                next_server_ips = []
                for rrset in response.additional:
                    if rrset.rdtype == dns.rdatatype.A:
                        next_server_ips.append(str(rrset[0]))
                
                # If we have glue records, use them
                if next_server_ips:
                    # Cache delegation for the zone if known
                    if zone_name is not None:
                        DELEGATION_CACHE[zone_name] = list(dict.fromkeys(next_server_ips))
                    recursive_response = _lookup_recursive(target_name, qtype, next_server_ips)
                    if recursive_response:
                        return recursive_response
                else:
                    # Unglued case: need to resolve NS names to IPs (try all NS names)
                    collected_limit = 3  # resolve a few NS names to get started faster
                    for ns_idx, ns_name in enumerate(ns_names):
                        ns_dns_name = dns.name.from_text(ns_name)
                        
                        # Avoid infinite loops
                        if (ns_dns_name, dns.rdatatype.A) in RESOLVING:
                            continue
                        
                        # Check cache first
                        ns_cache_key = (ns_dns_name, dns.rdatatype.A)
                        if ns_cache_key in CACHE:
                            ns_response = CACHE[ns_cache_key]
                        else:
                            # Mark as resolving
                            RESOLVING.add(ns_cache_key)
                            try:
                                ns_response = _lookup_recursive(ns_dns_name, dns.rdatatype.A, list(ROOT_SERVERS))
                            finally:
                                RESOLVING.discard(ns_cache_key)
                        
                        if ns_response and ns_response.answer:
                            for rrset in ns_response.answer:
                                if rrset.rdtype == dns.rdatatype.A:
                                    for rr in rrset:
                                        next_server_ips.append(str(rr))
                        # If we have collected enough IPs, move on to query them
                        if len(next_server_ips) >= collected_limit:
                            break
                    # Deduplicate and cache delegation if we discovered IPs
                    if next_server_ips:
                        next_server_ips = list(dict.fromkeys(ip for ip in next_server_ips if ':' not in ip))
                        if zone_name is not None:
                            DELEGATION_CACHE[zone_name] = next_server_ips
                    
                    if next_server_ips:
                        recursive_response = _lookup_recursive(target_name, qtype, next_server_ips)
                        if recursive_response:
                            return recursive_response
            
        except (dns.exception.Timeout, OSError):
            continue
        except Exception:
            continue

    return None

def lookup(target_name: dns.name.Name,
           qtype: int) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """
    global CACHE
    
    original_target = target_name
    original_qtype = qtype
    
    # Check cache at the very beginning
    cache_key = (target_name, qtype)
    if cache_key in CACHE:
        return CACHE[cache_key]

    # Accumulate all answer sections (to capture full CNAME chain)
    all_answers = []
    
    # Loop to handle CNAME restarts
    cname_chain_count = 0
    while cname_chain_count < 10:  # Prevent infinite CNAME loops
        # Start the recursive lookup process using best-known delegation if available
        # Find closest ancestor zone we have cached
        start_servers = None
        current = target_name
        while True:
            if current in DELEGATION_CACHE and DELEGATION_CACHE[current]:
                start_servers = DELEGATION_CACHE[current]
                break
            if len(current.labels) <= 1:  # reached root
                break
            current = current.parent()
        if not start_servers:
            start_servers = list(ROOT_SERVERS)

        response = _lookup_recursive(target_name, qtype, start_servers)
        
        # If the lookup failed completely, return what we have or empty
        if not response or not response.answer:
            if all_answers:
                # We have some answers from previous CNAME lookups
                query = dns.message.make_query(original_target, original_qtype)
                final_response = dns.message.make_response(query)
                for ans in all_answers:
                    final_response.answer.append(ans)
                CACHE[(original_target, original_qtype)] = final_response
                return final_response
            query = dns.message.make_query(original_target, original_qtype)
            empty_response = dns.message.make_response(query)
            result = empty_response if response is None else response
            CACHE[(original_target, original_qtype)] = result
            return result

        # Add current response answers to our accumulator
        for ans in response.answer:
            all_answers.append(ans)

        # Check the answer section for the record type we want.
        found_final_answer = False
        for rrset in response.answer:
            if rrset.rdtype == qtype:
                found_final_answer = True
                break
        
        if found_final_answer:
            # Build final response with all accumulated answers
            query = dns.message.make_query(original_target, original_qtype)
            final_response = dns.message.make_response(query)
            for ans in all_answers:
                final_response.answer.append(ans)
            CACHE[(original_target, original_qtype)] = final_response
            return final_response
        
        # Check for a CNAME instead.
        found_cname = False
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                new_name_str = str(rrset[0])
                target_name = dns.name.from_text(new_name_str)
                found_cname = True
                cname_chain_count += 1
                break
        
        if found_cname:
            continue
        
        # If we got an answer but it's neither what we asked for nor a CNAME
        query = dns.message.make_query(original_target, original_qtype)
        final_response = dns.message.make_response(query)
        for ans in all_answers:
            final_response.answer.append(ans)
        CACHE[(original_target, original_qtype)] = final_response
        return final_response
    
    # Too many CNAMEs in chain
    query = dns.message.make_query(original_target, original_qtype)
    final_response = dns.message.make_response(query)
    for ans in all_answers:
        final_response.answer.append(ans)
    CACHE[(original_target, original_qtype)] = final_response
    return final_response

def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    
    start_time = time.time()
    for a_domain_name in program_args.name:
        # Clear RESOLVING set for each new domain to avoid blocking legitimate lookups
        RESOLVING.clear()
        domain_start = time.time()
        print_results(collect_results(a_domain_name))
        domain_end = time.time()
        if program_args.verbose:
            print(f"[Time for {a_domain_name}: {domain_end - domain_start:.3f}s]")
    
    total_time = time.time() - start_time
    if program_args.verbose:
        print(f"[Total execution time: {total_time:.3f}s]")

if __name__ == "__main__":
    main()