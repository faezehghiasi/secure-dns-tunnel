import socket ,base64
from crypto_utils.crypto_module import decrypt_message
from base32_utils.base32 import decode_base32
port =53535
ip = "127.0.0.1"
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((ip , port))

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



def decrypt(enMass):

    global MessageStorage
    #****** Decode the massage with base32
    AESMass =b''
    for en in enMass:
        AESMass+=decode_base32(en)

    #***** Decrypte the massage
    deMass=decrypt_message(AESMass)

    #******* Get the sequence number*****
    deMass=deMass.decode()
    SequenceNumber = deMass.split('|')[0]
    content = deMass[deMass.find('|')+1:]
    MessageStorage[int(SequenceNumber)]= content
    if content.strip().endswith("END"):
        ordered = dict(sorted(MessageStorage.items(), key=lambda x: int(x[0])))
        full_message = ''.join(ordered.values())
        print("Full message reconstructed:")
        print(full_message)
        MessageStorage.clear()

    return SequenceNumber

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

    encryptedMassage = ''.join(domainName[:-3])


    QuestionSection= buildQuestion(domainName,Qtype)
    AnswerSection = buildAnswer(encryptedMassage)

    dnsBody=QuestionSection + AnswerSection
    return dnsHeader+ dnsBody




while 1:
    data , addr=sock.recvfrom(512)
    response=buildResponse(data)
    sock.sendto(response ,addr)
