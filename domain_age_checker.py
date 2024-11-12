import streamlit as st
import whois
import socket
import dns.resolver
from datetime import datetime


# Function to calculate domain age
def get_domain_age(domain_name):
    try:
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        if not creation_date:
            return None, "Could not find creation date."

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        today = datetime.now()
        age = today - creation_date
        years = age.days // 365
        months = (age.days % 365) // 30
        days = (age.days % 365) % 30

        return f"{years} years, {months} months, {days} days", creation_date
    except Exception as e:
        return None, f"Error: {e}"


# Function to check spam reputation and calculate approximate spam score
def check_spam_score(domain_name):
    # List of DNSBLs
    dnsbl_list = [
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "bl.spamcop.net",
    ]
    try:
        # Strip out protocols and www to ensure clean domain name
        domain_name = domain_name.replace("http://", "").replace("https://", "").replace("www.", "")
        ip_address = socket.gethostbyname(domain_name)
        spam_listed = []

        # Check each DNSBL list
        for dnsbl in dnsbl_list:
            try:
                query = '.'.join(reversed(ip_address.split("."))) + "." + dnsbl
                dns.resolver.resolve(query, "A")
                spam_listed.append(dnsbl)
            except dns.resolver.NXDOMAIN:
                pass  # IP not listed in this DNSBL
            except Exception:
                continue

        # Calculate spam score as a percentage
        spam_score_percentage = (len(spam_listed) / len(dnsbl_list)) * 100

        if spam_listed:
            return f"Listed on {len(spam_listed)} out of {len(dnsbl_list)} spam lists", f"{spam_score_percentage:.2f}%"
        else:
            return "Not listed on common spam lists.", "0%"
    except socket.gaierror:
        return "Error: Invalid domain name or DNS resolution failed.", "N/A"
    except Exception as e:
        return f"Error checking spam reputation: {e}", "N/A"


# Streamlit UI
st.title("Domain Age and Spam Score Checker")
domain_name = st.text_input("Enter the domain name (e.g., example.com):")

if st.button("Check Domain Info"):
    if domain_name:
        age, creation_date = get_domain_age(domain_name)
        spam_reputation, spam_score = check_spam_score(domain_name)

        st.write(f"**Domain:** {domain_name}")
        st.write(f"**Creation Date:** {creation_date}")
        st.write(f"**Domain Age:** {age}")
        st.write(f"**Spam Reputation:** {spam_reputation}")
        st.write(f"**Spam Score:** {spam_score}")
    else:
        st.warning("Please enter a domain name.")
