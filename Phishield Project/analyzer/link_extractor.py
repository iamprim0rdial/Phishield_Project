from bs4 import BeautifulSoup
import re

def extract_links(text):

    links = []

    # Extract raw URLs → convert to dict
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    raw_links = re.findall(url_pattern, text)

    for url in raw_links:
        links.append({
            "href": url,
            "text": url
        })

    # Extract HTML links
    soup = BeautifulSoup(text, "html.parser")

    for a_tag in soup.find_all("a", href=True):
        links.append({
            "href": a_tag["href"],
            "text": a_tag.get_text().strip()
        })

    return links