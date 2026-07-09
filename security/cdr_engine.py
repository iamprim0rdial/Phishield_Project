from bs4 import BeautifulSoup

#Content Disarm and Reconstruction (CDR)

def sanitize_email(html_content: str) -> str:
    """
    Aggressively neutralizes HTML to prevent one-click infections or tracking.
    Uses pure-text modifications and Base64 embedding to ensure zero network exposure.
    """
    if not html_content or not isinstance(html_content, str):
        return "No HTML content available."

    # Parse using standard built-in parser
    soup = BeautifulSoup(html_content, "html.parser")

    # 1. ☢️ REMOVE ACTIVE CONTENT (Scripts, Objects, Embeds)
    # Deletes execution vectors completely from the DOM tree
    for dangerous in soup.find_all(["script", "iframe", "object", "embed", "applet", "meta", "link"]):
        dangerous.decompose()

    # 2. 🔗 NEUTRALIZE LINKS
    # Disarms link targets while preserving destination visibility on hover
    for a in soup.find_all("a", href=True):
        original_url = a['href']

        a['href'] = "#"
        a['title'] = f"Original Link: {original_url}"
        a.append(f" [Link Neutralized]")

        # Style to look visibly disabled to the human eye
        a['style'] = "color: #d9534f; text-decoration: line-through; cursor: not-allowed; font-weight: bold;"

    # 3. 🖼️ NEUTRALIZE IMAGES (Zero-Network-Call Local Placeholder)
    # Fix: Replaced external link with an inline 1x1 gray pixel to stop 'phone-home' signal leaks
    safe_pixel = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

    for img in soup.find_all("img"):
        img['src'] = safe_pixel
        img['alt'] = "Image removed for safety"
        img['style'] = "border: 1px dashed #cccccc; width: 40px; height: 40px; display: inline-block;"

    # 4. 🧼 SCRUB ATTRIBUTES (Event Handler Purge)
    for tag in soup.find_all():
        # Prevent 'dictionary changed during iteration' exceptions
        attrs_to_del = [attr for attr in tag.attrs if attr.lower().startswith("on")]
        for attr in attrs_to_del:
            del tag.attrs[attr]

        # Intercept legacy styling attacks (e.g., old IE expression exploits)
        if tag.has_attr('style'):
            if "expression" in str(tag['style']).lower():
                del tag['style']

    # 5. 🧱 STRUCTURAL WRAPPING (Inject Warning Indicator)
    warning_banner = soup.new_tag(
        "div",
        style=(
            "background-color: #fff3cd; color: #856404; padding: 15px; "
            "border: 1px solid #ffeeba; margin-bottom: 20px; "
            "font-family: Arial, sans-serif; font-size: 14px; text-align: left; "
            "border-radius: 4px; font-weight: bold;"
        )
    )
    warning_banner.string = "⚠️ PhiShield CDR: This email has been sanitized. Active content, images, and external links have been safely stripped."

    # Insert clean notification layout cleanly at top
    if soup.body:
        soup.body.insert(0, warning_banner)
    else:
        soup.insert(0, warning_banner)

    return soup.prettify()
