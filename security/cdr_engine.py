from bs4 import BeautifulSoup
import re


def sanitize_email(html_content):
    """
    Aggressively neutralizes HTML to prevent one-click infections or tracking.
    """
    if not html_content:
        return "No HTML content available."

    soup = BeautifulSoup(html_content, "html.parser")

    # 1. ☢️ REMOVE ACTIVE CONTENT (Scripts, Objects, Embeds)
    # These are never needed in a safe preview
    for dangerous in soup.find_all(["script", "iframe", "object", "embed", "applet", "meta"]):
        dangerous.decompose()

    # 2. 🔗 NEUTRALIZE LINKS (The most important part)
    # We change hrefs to a safe internal redirect or a dead link
    for a in soup.find_all("a", href=True):
        original_url = a['href']
        # Replace with a safe 'Refanged' text version
        a['href'] = "#"
        a['title'] = f"Original Link: {original_url}"
        a.append(f" [Link Neutralized]")
        # Style it to look disabled
        a['style'] = "color: #d9534f; text-decoration: line-through; cursor: not-allowed;"

    # 3. 🖼️ NEUTRALIZE IMAGES (Prevent tracking pixels)
    # We replace images with a placeholder to prevent 'phone-home' signals
    for img in soup.find_all("img"):
        img['src'] = "https://placehold.co/600x400?text=Security+Placeholder"
        img['alt'] = "Image removed for safety"

    # 4. 🧼 SCRUB ATTRIBUTES
    # Remove event handlers (onclick, onerror, etc.)
    for tag in soup.find_all():
        # Create a list of keys to delete to avoid 'dict changed during iteration'
        attrs_to_del = [attr for attr in tag.attrs if attr.startswith("on")]
        for attr in attrs_to_del:
            del tag.attrs[attr]

        # Remove style expressions (old IE exploit)
        if tag.has_attr('style'):
            if "expression" in tag['style'].lower():
                del tag['style']

    # 5. 🧱 STRUCTURAL WRAPPING
    # Wrap the whole thing in a warning banner
    warning_banner = soup.new_tag("div",
                                  style="background: #fff3cd; color: #856404; padding: 15px; border: 1px solid #ffeeba; margin-bottom: 20px; font-family: sans-serif;")
    warning_banner.string = "⚠️ PhiShield CDR: This email has been sanitized. Active content and external links have been disabled for your protection."

    if soup.body:
        soup.body.insert(0, warning_banner)
    else:
        # If no body tag, just prepend it
        soup.insert(0, warning_banner)

    return soup.prettify()