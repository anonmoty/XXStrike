import requests
from bs4 import BeautifulSoup
from core.colors import Colors as C
from core.config import Config

class StoredXSS:
    name = "Stored XSS Tester"

    def __init__(self, url):
        self.url = url

    def run(self):
        print(f"\n{C.BLUE}{'=' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}💾 STORED XSS ANALYSIS{C.RESET}")
        print(f"{C.BLUE}{'=' * 60}{C.RESET}")

        results = {"forms_with_storage": [], "risk_indicators": []}

        try:
            resp = requests.get(self.url, timeout=Config.TIMEOUT, headers=Config.HEADERS)
            soup = BeautifulSoup(resp.text, 'html.parser')

            storage_keywords = ['comment', 'review', 'feedback', 'message',
                              'post', 'reply', 'note', 'bio', 'description',
                              'profile', 'about', 'content', 'body', 'text']

            forms = soup.find_all('form')
            print(f"  {C.info(f'Forms found: {len(forms)}')}")

            for i, form in enumerate(forms):
                action = form.get('action', 'self')
                inputs = form.find_all(['input', 'textarea'])
                textarea_count = len(form.find_all('textarea'))

                is_storage_candidate = False
                matched_keywords = []

                for inp in inputs:
                    name = inp.get('name', '').lower()
                    inp_id = inp.get('id', '').lower()
                    placeholder = inp.get('placeholder', '').lower()
                    combined = f"{name} {inp_id} {placeholder}"

                    for kw in storage_keywords:
                        if kw in combined:
                            is_storage_candidate = True
                            matched_keywords.append(kw)

                if is_storage_candidate or textarea_count > 0:
                    results["forms_with_storage"].append({
                        "form_index": i,
                        "action": action,
                        "keywords": list(set(matched_keywords)),
                        "textareas": textarea_count
                    })
                    print(f"\n    {C.warning(f'Form #{i}: Potential stored XSS vector')}")
                    print(f"      {C.DIM}Action: {action}{C.RESET}")
                    if matched_keywords:
                        kw_str = ', '.join(set(matched_keywords))
                        print(f"      {C.DIM}Keywords: {kw_str}{C.RESET}")
                    if textarea_count:
                        print(f"      {C.DIM}Textareas: {textarea_count} (rich input){C.RESET}")

            user_content_indicators = ['class="comment"', 'class="review"',
                                      'class="post"', 'class="message"',
                                      'class="user-content"', 'class="reply"']

            body = resp.text.lower()
            for indicator in user_content_indicators:
                if indicator in body:
                    results["risk_indicators"].append(indicator)

            if results["forms_with_storage"]:
                storage_count = len(results['forms_with_storage'])
                print(f"\n  {C.YELLOW}[!] {storage_count} forms may store user input{C.RESET}")
                print(f"  {C.DIM}Manual testing recommended for stored XSS{C.RESET}")
            else:
                print(f"\n  {C.safe('No obvious stored XSS vectors found')}")

        except Exception as e:
            print(f"  {C.error(f'Stored XSS analysis failed: {e}')}")

        return results
