# Written by REZA TORABI and Developed by phonix.

import re
import argparse
import phonenumbers
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from email_validator import validate_email, EmailNotValidError
import pyclip

# Email and Phone Number Extraction Constants
EMAIL_REGEX = r"[\w.-]+@[\w.-]+\.\w+"
PHONE_REGEX = r"\+?\d[\d\s\-()]{7,}\d"

# --- Core Extraction Functions ---
def is_valid_email(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def extract_emails(text):
    emails = {
        validate_email(email).email
        for email in re.findall(EMAIL_REGEX, text)
        if is_valid_email(email)
    }
    return sorted(emails)

def extract_phone_numbers(text, region="US"):
    phones = set()
    for match in re.findall(PHONE_REGEX, text):
        try:
            parsed = phonenumbers.parse(match, region)
            if phonenumbers.is_valid_number(parsed):
                formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                phones.add(formatted)
        except phonenumbers.NumberParseException:
            continue
    return sorted(phones)

def find_duplicates(items):
    seen, duplicates = set(), set()
    for item in items:
        if item in seen:
            duplicates.add(item)
        seen.add(item)
    return sorted(duplicates)

def extract_summary(text):
    emails = extract_emails(text)
    phones = extract_phone_numbers(text)
    domains = sorted({email.split("@")[1] for email in emails})
    country_codes = sorted({
        str(phonenumbers.parse(phone).country_code)
        for phone in phones
        if phonenumbers.is_valid_number(phonenumbers.parse(phone))
    })
    return {
        "emails": emails,
        "phones": phones,
        "email_count": len(emails),
        "phone_count": len(phones),
        "domains": domains,
        "country_codes": country_codes,
        "duplicate_emails": find_duplicates(emails),
        "duplicate_phones": find_duplicates(phones)
    }

def filter_emails_by_domain(emails, domain):
    return sorted([e for e in emails if e.lower().endswith(f"@{domain.lower()}")])

def filter_phones_by_country_code(phones, code):
    return sorted([p for p in phones if p.startswith(f"+{code}")])

# --- Output and Summary Utilities ---
def save_summary_to_file(summary, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"Valid Emails ({summary['email_count']}):\n")
        f.writelines(f" - {email}\n" for email in summary['emails'])

        f.write(f"\nValid Phone Numbers ({summary['phone_count']}):\n")
        f.writelines(f" - {phone}\n" for phone in summary['phones'])

        f.write("\nEmail Domains:\n")
        f.writelines(f" - {domain}\n" for domain in summary['domains'])

        f.write("\nPhone Country Codes:\n")
        f.writelines(f" - {code}\n" for code in summary['country_codes'])

        if summary['duplicate_emails']:
            f.write("\nDuplicate Emails:\n")
            f.writelines(f" - {email}\n" for email in summary['duplicate_emails'])

        if summary['duplicate_phones']:
            f.write("\nDuplicate Phone Numbers:\n")
            f.writelines(f" - {phone}\n" for phone in summary['duplicate_phones'])

def print_summary(summary):
    print(f"\nValid Emails ({summary['email_count']}):")
    print("\n".join(f" - {email}" for email in summary['emails']))

    print(f"\nValid Phone Numbers ({summary['phone_count']}):")
    print("\n".join(f" - {phone}" for phone in summary['phones']))

    print("\nEmail Domains:")
    print("\n".join(f" - {domain}" for domain in summary['domains']))

    print("\nPhone Country Codes:")
    print("\n".join(f" - {code}" for code in summary['country_codes']))

    if summary['duplicate_emails']:
        print("\nDuplicate Emails:")
        print("\n".join(f" - {email}" for email in summary['duplicate_emails']))

    if summary['duplicate_phones']:
        print("\nDuplicate Phone Numbers:")
        print("\n".join(f" - {phone}" for phone in summary['duplicate_phones']))

def copy_to_clipboard(text):
    pyclip.copy(text)

# --- Graphical User Interface ---
def run_gui():
    def load_file():
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                input_text.delete("1.0", tk.END)
                input_text.insert(tk.END, f.read())

    def extract_info():
        text = input_text.get("1.0", tk.END)
        summary = extract_summary(text)
        result = (
            f"Valid Emails ({summary['email_count']}):\n" + "\n".join(summary['emails']) +
            f"\n\nValid Phone Numbers ({summary['phone_count']}):\n" + "\n".join(summary['phones']) +
            "\n\nEmail Domains:\n" + "\n".join(summary['domains']) +
            "\n\nPhone Country Codes:\n" + "\n".join(summary['country_codes'])
        )
        if summary['duplicate_emails']:
            result += "\n\nDuplicate Emails:\n" + "\n".join(summary['duplicate_emails'])
        if summary['duplicate_phones']:
            result += "\n\nDuplicate Phone Numbers:\n" + "\n".join(summary['duplicate_phones'])

        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, result)

    def copy_results():
        result = result_box.get("1.0", tk.END).strip()
        if result:
            copy_to_clipboard(result)
            messagebox.showinfo("Copied", "Results copied to clipboard.")
        else:
            messagebox.showwarning("No Data", "No results to copy.")

    root = tk.Tk()
    root.title("Email & Phone Number Extractor")
    root.geometry("850x700")

    tk.Button(root, text="Load Text File", command=load_file).pack(pady=5)
    tk.Label(root, text="Input Text:").pack()
    input_text = scrolledtext.ScrolledText(root, height=10)
    input_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    tk.Button(root, text="Extract", command=extract_info).pack(pady=5)
    tk.Button(root, text="Copy Results to Clipboard", command=copy_results).pack(pady=5)
    tk.Label(root, text="Results:").pack()
    result_box = scrolledtext.ScrolledText(root, height=15)
    result_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    root.mainloop()

# --- Main CLI Execution ---
def main(file_path, output_path=None):
    with open(file_path, "r", encoding="utf-8") as file:
        text = file.read()
    summary = extract_summary(text)
    print_summary(summary)
    if output_path:
        save_summary_to_file(summary, output_path)
        print(f"\nSummary saved to: {output_path}")

# --- Pytest Unit Tests ---
def test_is_valid_email():
    assert is_valid_email("test@example.com")
    assert not is_valid_email("invalid-email")

def test_extract_emails():
    text = """
    Contact me at john.doe@example.com and jane.doe@website.org.
    Invalid email: john.doe@website@org.
    """
    assert extract_emails(text) == ["jane.doe@website.org", "john.doe@example.com"]

def test_extract_phone_numbers():
    text = """
    Call me at +1-800-555-1234 or (800) 555-5678.
    Invalid phone: 12345.
    """
    assert extract_phone_numbers(text) == ["+18005551234", "+18005555678"]

def test_find_duplicates():
    assert find_duplicates(["test@example.com", "john.doe@example.com", "test@example.com"]) == ["test@example.com"]
    assert find_duplicates(["unique@example.com", "another@example.com"]) == []

# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract emails and phone numbers from a text file or launch GUI.")
    parser.add_argument("file", nargs="?", help="Path to input text file")
    parser.add_argument("--output", help="Optional output file to save summary")
    parser.add_argument("--gui", action="store_true", help="Launch graphical user interface")
    args = parser.parse_args()

    if args.gui:
        run_gui()
    elif args.file:
        main(args.file, args.output)
    else:
        print("Please provide a file path or use --gui to launch the GUI.")
 
