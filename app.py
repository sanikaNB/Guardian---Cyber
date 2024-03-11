from flask import Flask,request,jsonify
import pickle
import numpy as np
import string
import nltk
from nltk import pos_tag

def tokenize_remove_punctuation(text):
    clean_text=[]
    text=text.split(" ")
    for word in text:
        word=list(word)
        new_word=[]
        for c in word:
            if c not in string.punctuation:
                new_word.append(c)
            word="".join(new_word)
        clean_text.append(word)
    return clean_text

stopwords = nltk.corpus.stopwords.words('english')
def remove_stopwords(text):
  clean_text = []
  for word in text:
    if word not in stopwords:
      clean_text.append(word)
  return clean_text

def pos_tagging(text):
    try:
        tagged = nltk.pos_tag(text)
        return tagged
    except Exception as e:
        print(e)

from nltk.corpus import wordnet


def get_wordnet(pos_tag):
    if pos_tag.startswith('J'):
        return wordnet.ADJ
    elif pos_tag.startswith('V'):
        return wordnet.VERB
    elif pos_tag.startswith('N'):
        return wordnet.NOUN
    elif pos_tag.startswith('R'):
        return wordnet.ADV
    else:
        return wordnet.NOUN


from nltk.stem import WordNetLemmatizer


def clean_text(text):
    text = str(text)

    text = text.lower()

    text = tokenize_remove_punctuation(text)

    text = [word for word in text if not any(c.isdigit() for c in word)]

    text = remove_stopwords(text)

    text = [t for t in text if len(t) > 0]

    pos_tags = pos_tagging(text)

    text = [WordNetLemmatizer().lemmatize(t[0], get_wordnet(t[1])) for t in pos_tags]
    text = [t for t in text if len(t) > 1]

    text = " ".join(text)
    return text


data=pickle.load(open('saved_steps.pkl','rb'))
regressor_data= data["model"]
y=data["comments"]


app=Flask(__name__)

@app.route('/')
def home():
    return "hello world"

@app.route('/predict',methods=['POST'])
def predict():
    text=request.form.get('text')
    text = clean_text(text)
    l_text = text.split()
    x = y.transform(l_text)
    answer = regressor_data.predict(x)

    result=answer.tolist()
    return jsonify({'result':result})







import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
import whois
from datetime import datetime
from googlesearch import search
import socket


def usingip(url):
    try:
        # Extract the hostname from the URL
        hostname = re.sub(r'^https?://', '', url).split('/')[0]

        # Check if the hostname is an IP address
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
            return 1  # URL is using an IP address
        else:
            return -1  # URL is not using an IP address
    except Exception as e:
        print(f"Error: {e}")
        return -1


def long_length(U_R_L):
    if (len(U_R_L) > 75):
        return 1
    return 0


def short_length(U_R_L):
    if (len(U_R_L) <= 75):
        return 1
    return 0


def findSymbol(U_R_L):
    i = 0
    while (i < len(U_R_L)):
        if (U_R_L[i] == "@"):
            return 1
        i += 1
    return -1


def redirectingg(U_R_L):
    i = 0
    while (i < len(U_R_L)):
        if (U_R_L[i:i + 5] == ".com/"):
            return 1
        i += 1
    return -1


def prefixsuffix(url):
    prefixes = ["http://", "https://", "ftp://", "ftps://", "www."]
    suffixes = [".com", ".net", ".org", ".edu", ".gov", ".io", ".info"]

    # Check if URL starts with a prefix
    for prefix in prefixes:
        if url.startswith(prefix):
            return 1  # URL has a prefix

    # Check if URL ends with a suffix
    for suffix in suffixes:
        if url.endswith(suffix):
            return 1  # URL has a suffix
    return -1


def classify_url_with_subdomain(U_R_L):
    parsed_url = urlparse(U_R_L)
    hostname_parts = parsed_url.hostname.split('.')

    if len(hostname_parts) > 2:
        return 1  # Subdomain present
    elif len(hostname_parts) == 2:
        return 0  # No subdomain
    else:
        return -1  # Invalid URL


def hhtps(U_R_L):
    if (U_R_L[0:5] == "https"):
        return 1
    return 0


def domainreglen(url):
    try:
        # Extract the domain name from the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Check if "raglan" is present in the domain name
        if "raglan" in domain.lower():
            return 1  # URL domain contains "raglan"
        else:
            return -1  # URL domain does not contain "raglan"
    except Exception as e:
        print(f"Error: {e}")
        return -1


def favicon(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find <link> tags with rel attribute set to "icon" or "shortcut icon"
        favicon_link = soup.find('link', rel=['icon', 'shortcut icon'])

        # Check if favicon link is found
        if favicon_link and 'href' in favicon_link.attrs:
            return 1  # URL has favicon
        else:
            return -1  # URL does not have favicon
    except requests.exceptions.RequestException:
        return -1


def nonStandardPort(url):
    standard_ports = {
        "http": 80,
        "https": 443,
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "dns": 53,
        "http_proxy": 8080,
        "pop3": 110,
        "imap": 143,
        "ldap": 389,
        "https_proxy": 8443,
        "mysql": 3306,
        "rdp": 3389,
        "sftp": 22  # Same as SSH
    }

    try:
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme.lower()
        port = parsed_url.port

        if port and port != standard_ports.get(scheme):
            return 1  # URL is using a non-standard port
        else:
            return -1  # URL is not using a non-standard port
    except Exception as e:
        print(f"Error: {e}")
        return -1


def httpsdomain(url):
    try:
        # Extract the scheme part from the URL
        scheme = url.split(':')[0]

        if scheme == "https":
            return 1  # URL is using HTTPS
        else:
            return -1  # URL is not using HTTPS
    except Exception as e:
        print(f"Error: {e}")
        return -1


def requestURL(U_R_L):
    response = requests.get(U_R_L)
    request_url = response.request.url
    if request_url == " ":
        return -1
    return 1


def anchorURL(U_R_L):
    parsed_url = urlparse(U_R_L)
    if parsed_url.fragment:
        return 1  # Anchor URL present
    elif not parsed_url.fragment:
        return 0  # No anchor URL
    else:
        return -1


def LinksInScriptTags(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all <script> tags
        script_tags = soup.find_all('script')

        # Check if any <script> tag contains URLs that resemble links
        for script_tag in script_tags:
            script_content = str(script_tag)
            if re.search(r'(?i)<script[^>]*>.*\b(href|src)\b.*</script>', script_content):
                return 1  # URL has links within <script> tags

        return -1  # URL does not have links within <script> tags
    except requests.exceptions.RequestException:
        return -1


def ServerFormHandler(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all <form> tags with action attribute
        form_tags = soup.find_all('form', action=True)

        # Check if any form has a server-side form handler
        for form_tag in form_tags:
            action_url = form_tag['action']
            if action_url.startswith('http') or action_url.startswith('/'):
                return 1  # Server-side form handler found

        return -1  # No server-side form handler found
    except requests.exceptions.RequestException:
        return -1


def is_info_email(url):
    email_pattern = r'^\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$'

    if re.match(email_pattern, url):
        username, domain = url.split('@')
        if username.lower() == 'info':
            return 1
    return -1


def is_abnormal_url(url):
    abnormal_patterns = [
        r'\b\d{5,}\b',  # Contains 5 or more consecutive digits
        r'[^\w\d\.-]',  # Contains non-alphanumeric and non-special characters
        r'\b(?:http|https)://',  # Contains both HTTP and HTTPS schemes
        r'\.\.'  # Contains double dot (..)
    ]

    # Check if the URL matches any abnormal pattern
    for pattern in abnormal_patterns:
        if re.search(pattern, url):
            return 1
    return -1


def classify_url_forwarding(url):
    try:
        response = requests.head(url, allow_redirects=True)
        status_code = response.status_code
        if status_code in [301, 302]:  # Redirect status codes
            return 1  # Website forwarding present
        else:
            return 0  # No website forwarding
    except requests.exceptions.RequestException:
        return -1  # Error occurred


def statusbarcust(url):
    try:
        # Retrieve the HTML content of the webpage
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        html_content = response.content

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Search for JavaScript code or event handlers that modify the status bar
        script_tags = soup.find_all('script')
        for script_tag in script_tags:
            if 'onmouseover' in script_tag.get_text():
                return 1  # URL has custom status bar
        return -1  # URL does not have custom status bar
    except Exception as e:
        print(f"Error: {e}")
        return -1  # Error occurred


def classify_disable_right_click(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Search for JavaScript code that disables right-click functionality
        script_tags = soup.find_all('script')
        for script_tag in script_tags:
            if 'oncontextmenu' in script_tag.get_text():
                return 1  # Right-click disabled

        return -1  # Right-click not disabled
    except requests.exceptions.RequestException:
        return -1  # Error occurred


def classify_using_popup_window(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Search for JavaScript code that uses popup windows
        script_tags = soup.find_all('script')
        for script_tag in script_tags:
            if 'window.open(' in script_tag.get_text():
                return 1  # Using popup window

        return -1  # Not using popup window
    except requests.exceptions.RequestException:
        return -1  # Error occurred


def IframeRedirection(url):
    """
    Classify the URL based on the presence of iframe redirection.

    :param url: The URL to classify.
    :return: 1 if iframe redirection used, -1 if not used or error occurred.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Search for <iframe> tags with src attribute pointing to a different URL
        iframe_tags = soup.find_all('iframe')
        for iframe_tag in iframe_tags:
            if iframe_tag.get('src') and iframe_tag['src'] != url:
                return 1  # Iframe redirection used

        return -1  # Iframe redirection not used
    except requests.exceptions.RequestException:
        return -1


def AgeofDomain(url):
    try:
        # Extract the domain name from the URL
        domain = url.split('/')[2]

        # Query WHOIS information for the domain
        domain_info = whois.whois(domain)

        # Extract the creation date from the WHOIS information
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            # For some domains, creation_date may be a list of dates
            creation_date = min(creation_date)

        # Calculate the age of the domain
        if creation_date is not None:
            today = datetime.now()
            age = (today - creation_date).days
            return age
        else:
            # Unable to determine creation date
            return -1
    except whois.parser.PywhoisError:
        # Error occurred during WHOIS query
        return -1


def DNSRecording(url):
    try:
        # Extract the hostname from the URL
        hostname = url.split('/')[2]

        # Resolve the hostname to an IP address
        ip_address = socket.gethostbyname(hostname)

        if ip_address:
            return 1  # URL has DNS records
        else:
            return -1  # URL does not have DNS records
    except Exception as e:
        print(f"Error: {e}")
        return -1


def WebsiteTraffic(url):
    api_key = ""
    try:
        # SimilarWeb API endpoint for website traffic
        endpoint = f"https://api.similarweb.com/v1/website/{url}/total-traffic-and-engagement"

        # Parameters for the request (including your API key)
        params = {
            "api_key": api_key,
        }

        # Make a GET request to the SimilarWeb API
        response = requests.get(endpoint, params=params)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response and extract the website traffic data
            data = response.json()
            total_visits = data.get("visits", "N/A")
            return total_visits
        else:
            return -1  # Request failed
    except Exception as e:
        print(f"Error: {e}")
        return -1  # Error occurred


def PageRank(url):
    try:
        # Open PageRank API endpoint for URL metrics
        endpoint = f"https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D={url}"

        # Optional: Provide your Open PageRank API key if required
        api_key = ""
        headers = {'API-OPR': api_key} if api_key else {}

        # Make a GET request to the Open PageRank API
        response = requests.get(endpoint, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response and extract the page rank
            data = response.json()
            page_rank = data.get(url, {}).get("rank", "N/A")
            return page_rank
        else:
            return -1  # Request failed
    except Exception as e:
        print(f"Error: {e}")
        return -1


def GoogleIndex(url):
    try:
        # Perform a Google search query for the URL
        search_results = list(search(url, num=1, stop=1, pause=2))

        # Check if the URL appears in the search results
        if url in search_results:
            return 1  # URL is indexed by Google
        else:
            return 0  # URL is not indexed by Google
    except Exception as e:
        print(f"Error: {e}")
        return -1


def LinksPointingToPage(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all <a> tags with href attribute
        links = soup.find_all('a', href=True)

        # Check if any link points to the URL
        for link in links:
            if link['href'] == url:
                return 1  # URL has links pointing to it

        return 0  # URL has no links pointing to it
    except requests.exceptions.RequestException:
        return -1


def StatsReport(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Search for keywords or patterns that indicate the presence of stats report
        keywords = ["statistics", "analytics", "report", "insights"]
        for keyword in keywords:
            if keyword in soup.get_text().lower():
                return 1  # URL has stats report

        return -1  # URL does not have stats report
    except requests.exceptions.RequestException:
        return -1

data=pickle.load(open('URLDetection.pkl','rb'))
regressor= data["model"]

@app.route('/detect',methods=['POST'])
def detect():
    url=request.form.get('url')
    size = 31
    arr = [0] * size
    arr[0] = 1
    arr[1] = usingip(url)
    arr[2] = long_length(url)
    arr[3] = short_length(url)
    arr[4] = findSymbol(url)
    arr[5] = redirectingg(url)
    arr[6] = prefixsuffix(url)
    arr[7] = classify_url_with_subdomain(url)
    arr[8] = hhtps(url)
    arr[9] = domainreglen(url)
    arr[10] = favicon(url)
    arr[11] = nonStandardPort(url)
    arr[12] = httpsdomain(url)
    arr[13] = requestURL(url)
    arr[14] = anchorURL(url)
    arr[15] = LinksInScriptTags(url)
    arr[16] = ServerFormHandler(url)
    arr[17] = is_info_email(url)
    arr[18] = is_abnormal_url(url)
    arr[19] = classify_url_forwarding(url)
    arr[20] = statusbarcust(url)
    arr[21] = classify_disable_right_click(url)
    arr[22] = classify_using_popup_window(url)
    arr[23] = IframeRedirection(url)
    arr[24] = AgeofDomain(url)
    arr[25] = DNSRecording(url)
    arr[26] = WebsiteTraffic(url)
    arr[27] = PageRank(url)
    arr[28] = GoogleIndex(url)
    arr[29] = LinksPointingToPage(url)
    arr[30] = StatsReport(url)
    reshaped_array = np.array(arr).reshape(1, 31)
    answer = regressor.predict(reshaped_array)
    serializable_array = answer.tolist()

    # Return the serializable array as JSON
    return jsonify({'result': serializable_array})



if __name__=='__main__':
    app.run(debug=True)