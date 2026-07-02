from bs4 import BeautifulSoup
import re


def extract_links(text):
    links = []
    seen = set()

    # -------- RAW URL extraction --------
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    raw_links = re.findall(url_pattern, text)

    for url in raw_links:
        if url not in seen:
            links.append({
                "href": url,
                "text": url,
                "type": "raw"
            })
            seen.add(url)

    # -------- ONLY parse HTML if it looks like HTML --------
    if "<a" in text or "<html" in text:
        soup = BeautifulSoup(text, "html.parser")

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            anchor_text = a_tag.get_text().strip()

            if href not in seen:
                links.append({
                    "href": href,
                    "text": anchor_text,
                    "type": "html"
                })
                seen.add(href)

    return links