from uuid import uuid4
from OpenSSL import crypto

def create_self_signed_cert(organisation='Org', common_name = 'test', dname=None):
    valid_RDN_list = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress']

    # 创建密钥对
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)
    
    # 创建主题对象,用于设置证书的主题
    req = crypto.X509Req()  # 证书签名请求
    subj = req.get_subject()

    if dname:
        if not all(field in valid_RDN_list for field in dname):
            raise ValueError(f"Invalid DNAME recevied. Valid DNAME fileds are {valid_RDN_list}")
    else:
        dname = {"O": organisation, "CN": common_name}

    for k, v in dname.items():
        setattr(subj, k, v)

    # 创建自签名证书
    cert = crypto.X509()
    cert.set_subject(req.get_subject())
    # 设置序列号
    cert.set_serial_number(int(uuid4()))
    # 设置时间
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    # 设置颁发者
    cert.set_issuer(cert.get_subject())
    print(cert.get_subject())
    cert.set_pubkey(pkey)
    # 使用私钥和一个摘要算法对证书数据进行签名，确保证书的完整性和不能被篡改
    cert.sign(pkey, 'sha512')

    cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
    pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode('utf-8')
    with open('server.crt', 'w') as f:
        f.write(cert)
    with open('server.key', 'w') as f:
        f.write(pkey)
    return cert, pkey

create_self_signed_cert()