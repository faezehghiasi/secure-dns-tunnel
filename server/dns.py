import socket ,base64
from crypto_utils.crypto_module import decrypt_message
from base32_utils.base32 import decode_base32

port =53535
ip = "127.0.0.1"
SHARED_KEY = b'0123456789abcdef0123456789abcdef'

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((ip , port))

print("[✓] DNS Tunnel Server is running on port", port)

MessageStorage = {}

def getFlags(flags):
    QR = '0'
    OpCode=''

    # byte1=bytes(flags[:1])
    # byte2=bytes(flags[1:2])

    # for bit in range(1,5):
    #     OpCode+= str(ord(byte1)& (1<<bit))

#///////////////// اینجا رو نمیفهمم چرا چت گفت عوض کن تغییر بده

    byte1 = flags[0]
    for bit in range(1, 5):
     OpCode += str((byte1 & (1 << (7 - bit))) >> (7 - bit))

    AA='1'
    TC='0'
    RD='0'
    RA='0'
    Z='000'
    Rc='0000'

    return int(QR+OpCode+AA+TC+RD , 2).to_bytes(1,byteorder="big") + int(RA+Z+Rc ,2).to_bytes(1,byteorder="big")


def getQuestionDomain(data):
    state = 0
    expectedLength=0
    subdomain=''
    domainString =[]
    split=0
    cursor=0
    for byte in data:
        if state==1 :
            subdomain+= chr(byte)
            split+=1
            if split==expectedLength :
                domainString.append(subdomain)
                subdomain=''
                state =0
                split=0
            if byte==0 :
                break
        else : 
            state=1
            expectedLength= byte
        cursor+=1

    questionType=data [ cursor : cursor+2]
    return(domainString , questionType)


def buildQuestion(domainName,QType):
    qbyte = b''
    for part in domainName:
        length=len(part)
        qbyte += bytes([length])

        for char in part :
            qbyte+= ord(char).to_bytes(1,byteorder="big")
    # End of the domain
    qbyte+= (0).to_bytes(1,byteorder="big")

    # ***** If question type is "txt"
    if QType == b'\x00\x10':
        qbyte+= (1).to_bytes(2,byteorder="big")

    #******* for CLASS  IN*********
    qbyte+= (1).to_bytes(2,byteorder="big")

    return qbyte



def decrypt(enMass: str):

    global MessageStorage

    # 1) تمام رشتهٔ base32 را یک‌جا دیکود کن
    AESMass = decode_base32(enMass)

    # 2) رمزگشایی AES
    deMass = decrypt_message(AESMass, SHARED_KEY)

    # 3) استخراج شمارهٔ سکانس و محتوا
    deMass = deMass.decode()
    seq, content = deMass.split('|', 1)
    print(f"[INFO] Chunk received: seq={seq} content={content[:20]}...")  # ← اضافه شده
    MessageStorage[int(seq)] = content

    # 4) اگر قطعهٔ آخر رسید، پیام کامل را سرِ هم کن
    if content.endswith("<END>"):
        ordered = dict(sorted(MessageStorage.items()))
        full_message = ''.join(ordered.values()).removesuffix("<END>")
        print("\n[✓] Full message reconstructed:")
        print(full_message)
        MessageStorage.clear()

    return seq


def buildAnswer(enMass):
    SequenceNumber=decrypt(enMass)
    Ack="Ack for "+SequenceNumber
    NAME = b'\xc0\x0c'  

    TYPE = (16).to_bytes(2, byteorder='big')   # 16 = TXT record
    CLASS = (1).to_bytes(2, byteorder='big')   
    TTL = (0).to_bytes(4, byteorder='big')
    txtData=Ack.encode()
    RDLENGTH=(len(txtData)+1).to_bytes(2,byteorder="big")
    RDATA = bytes([len(txtData)]) + txtData  
    return NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
    



    
def buildResponse(data):
    #*******Transaction ID***********
    TransactionID= data[0:2]

    #********Get flags********
    Flags=getFlags(data[2:4])
    
    #***** Question Count ***********
    QDCount = (1).to_bytes(2, byteorder='big')

    #****** Answer Count **************
    ANCount= (1).to_bytes(2,byteorder="big")

    #****** Name server Count **************
    NSCount= (0).to_bytes(2,byteorder="big")

    #****** Additional Count **************
    ARCount= (0).to_bytes(2,byteorder="big")

    dnsHeader = TransactionID+Flags+QDCount+ANCount+NSCount+ARCount
    
    domainName ,Qtype = getQuestionDomain(data[12:])

    encryptedMassage = ''.join(domainName[:-3])  # ← مطمئن شو که فقط 3 label انتهایی base domain هستن

    QuestionSection= buildQuestion(domainName,Qtype)
    AnswerSection = buildAnswer(encryptedMassage)

    dnsBody=QuestionSection + AnswerSection
    return dnsHeader+ dnsBody



while 1:
    data , addr=sock.recvfrom(512)
    print(f"\n[+] Received DNS query from {addr}")
    response=buildResponse(data)
    sock.sendto(response ,addr)
