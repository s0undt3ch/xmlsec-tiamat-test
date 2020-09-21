import os
import sys
import lxml
import xmlsec
import pathlib
import tempfile
import traceback
from lxml import etree


consts = xmlsec.constants


PKG_DIR = pathlib.Path(getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))).resolve()
DATA_DIR = PKG_DIR / "data"
rsakey = str(DATA_DIR / "rsakey.pem")
rsapub = str(DATA_DIR / "rsapub.pem")
rsacert = str(DATA_DIR / "rsacert.pem")


def load( name):
    """loads resource by name"""
    with open(str(DATA_DIR / name), "rb") as stream:
        return stream.read()

def load_xml(name, xpath=None):
    """returns xml.etree"""
    root = etree.parse(str(DATA_DIR / name), parser=etree.XMLParser()).getroot()
    if xpath is None:
        return root
    return root.find(xpath)

def test_encrypt_xml():
    root = load_xml('enc1-in.xml')
    enc_data = xmlsec.template.encrypted_data_create(root, consts.TransformAes128Cbc, type=consts.TypeEncElement, ns="xenc")
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
    ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
    xmlsec.template.encrypted_data_ensure_cipher_value(ek)
    data = root.find('./Data')
    assert data is not None

    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file(rsacert, format=consts.KeyDataFormatCertPem))

    ctx = xmlsec.EncryptionContext(manager)
    ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

    encrypted = ctx.encrypt_xml(enc_data, data)
    assert encrypted is not None

    enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
    assert enc_method is not None
    assert enc_method.get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
    assert ki is not None
    enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
    assert enc_method2 is not None
    assert enc_method2.get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
    assert cipher_value is not None


def test_encrypt_binary():
    root = load_xml('enc2-in.xml')
    enc_data = xmlsec.template.encrypted_data_create(
        root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns="xenc", mime_type="binary/octet-stream"
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
    ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
    xmlsec.template.encrypted_data_ensure_cipher_value(ek)

    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file(rsacert, format=consts.KeyDataFormatCertPem))

    ctx = xmlsec.EncryptionContext(manager)
    ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

    encrypted = ctx.encrypt_binary(enc_data, b'test')
    assert encrypted is not None
    assert "{%s}%s" % (consts.EncNs, consts.NodeEncryptedData) == encrypted.tag

    enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
    assert enc_method is not None
    assert "http://www.w3.org/2001/04/xmlenc#aes128-cbc" == enc_method.get("Algorithm")

    ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
    assert ki is not None
    enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
    assert enc_method2 is not None
    assert "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" == enc_method2.get("Algorithm")
    cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
    assert cipher_value is not None

def test_encrypt_uri():
    root = load_xml('enc2-in.xml')
    enc_data = xmlsec.template.encrypted_data_create(
        root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns="xenc", mime_type="binary/octet-stream"
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
    ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
    xmlsec.template.encrypted_data_ensure_cipher_value(ek)

    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file(rsacert, format=consts.KeyDataFormatCertPem))

    ctx = xmlsec.EncryptionContext(manager)
    ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(b'test')

    encrypted = ctx.encrypt_binary(enc_data, 'file://' + tmpfile.name)
    assert encrypted is not None
    assert "{%s}%s" % (consts.EncNs, consts.NodeEncryptedData) == encrypted.tag

    enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
    assert enc_method is not None
    assert "http://www.w3.org/2001/04/xmlenc#aes128-cbc" == enc_method.get("Algorithm")

    ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
    assert ki is not None
    enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
    assert enc_method2 is not None
    assert "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" == enc_method2.get("Algorithm")
    cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
    assert cipher_value is not None

def test_decrypt1():
    check_decrypt(1)

def test_decrypt2():
    check_decrypt(2)

def test_decrypt_key():
    root = load_xml('enc3-out.xml')
    enc_key = xmlsec.tree.find_child(root, consts.NodeEncryptedKey, consts.EncNs)
    assert enc_key is not None

    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem))
    ctx = xmlsec.EncryptionContext(manager)
    keydata = ctx.decrypt(enc_key)
    ctx.reset()
    root.remove(enc_key)
    ctx.key = xmlsec.Key.from_binary_data(consts.KeyDataAes, keydata)
    enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
    assert enc_data is not None
    decrypted = ctx.decrypt(enc_data)
    assert decrypted is not None
    enc_in = load_xml("enc3-in.xml")
    enc_in_s = etree.tostring(enc_in)
    decrypted_s = etree.tostring(decrypted)
    assert enc_in_s == decrypted_s, "{!r} != {!r}".format(enc_in_s, decrypted_s)

def check_decrypt(i):
    enc_out = load_xml('enc%d-out.xml' % i)
    enc_data = xmlsec.tree.find_child(enc_out, consts.NodeEncryptedData, consts.EncNs)
    assert enc_data is not None

    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem))
    ctx = xmlsec.EncryptionContext(manager)
    decrypted = ctx.decrypt(enc_data)
    assert decrypted is not None
    enc_in = load_xml("enc%d-in.xml" % i)
    #print(1, etree.tostring(enc_in))
    #print(2, etree.tostring(enc_out))
    #print(3, etree.tostring(decrypted))
    enc_in_s = etree.tostring(enc_in)
    enc_out_s = etree.tostring(enc_out)
    assert enc_in_s == enc_out_s, "{!r} != {!r}".format(enc_in_s, enc_out_s)
    #assert enc_in == enc_out, "{!r} != {!r}".format(enc_in, enc_out)

def check_no_segfault():
    namespaces = {'soap': 'http://schemas.xmlsoap.org/soap/envelope/'}

    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file(rsacert, format=consts.KeyDataFormatCertPem)
    manager.add_key(key)
    template = load_xml('enc-bad-in.xml')
    enc_data = xmlsec.template.encrypted_data_create(
        template, xmlsec.Transform.AES128, type=xmlsec.EncryptionType.CONTENT, ns='xenc'
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
    enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.Transform.RSA_PKCS1)
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
    data = template.find('soap:Body', namespaces=namespaces)
    enc_ctx = xmlsec.EncryptionContext(manager)
    enc_ctx.key = xmlsec.Key.generate(xmlsec.KeyData.AES, 192, xmlsec.KeyDataType.SESSION)
    try:
        enc_ctx.encrypt_xml(enc_data, data)
    except Exception:
        pass
    else:
        print("exception not raised")
        exit(1)


def test_sign_case1():
    """Should sign a pre-constructed template file using a key from a PEM file."""
    root = load_xml("sign1-in.xml")
    sign = xmlsec.tree.find_node(root, consts.NodeSignature)
    assert sign is not None

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.name = 'rsakey.pem'
    assert "rsakey.pem" == ctx.key.name

    ctx.sign(sign)
    assert load_xml("sign1-out.xml") == root

def test_sign_case2():
    """Should sign a dynamicaly constructed template file using a key from a PEM file."""
    root = load_xml("sign2-in.xml")
    sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
    assert sign is not None
    root.append(sign)
    ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
    xmlsec.template.add_transform(ref, consts.TransformEnveloped)
    ki = xmlsec.template.ensure_key_info(sign)
    xmlsec.template.add_key_name(ki)

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.name = 'rsakey.pem'
    assert "rsakey.pem" == ctx.key.name

    ctx.sign(sign)
    assert load_xml("sign2-out.xml") == root

def test_sign_case3():
    """Should sign a file using a dynamicaly created template, key from PEM and an X509 cert."""
    root = load_xml("sign3-in.xml")
    sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
    assert sign is not None
    root.append(sign)
    ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
    xmlsec.template.add_transform(ref, consts.TransformEnveloped)
    ki = xmlsec.template.ensure_key_info(sign)
    xmlsec.template.add_x509_data(ki)

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.load_cert_from_file(rsacert, consts.KeyDataFormatPem)
    ctx.key.name = 'rsakey.pem'
    assert "rsakey.pem" == ctx.key.name

    ctx.sign(sign)
    assert load_xml("sign3-out.xml") == root

def test_sign_case4():
    """Should sign a file using a dynamically created template, key from PEM and an X509 cert with custom ns."""

    root = load_xml("sign4-in.xml")
    xmlsec.tree.add_ids(root, ["ID"])
    elem_id = root.get('ID', None)
    if elem_id:
        elem_id = '#' + elem_id
    sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns="ds")
    assert sign is not None
    root.append(sign)
    ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri=elem_id)
    xmlsec.template.add_transform(ref, consts.TransformEnveloped)
    xmlsec.template.add_transform(ref, consts.TransformExclC14N)
    ki = xmlsec.template.ensure_key_info(sign)
    xmlsec.template.add_x509_data(ki)

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.load_cert_from_file(rsacert, consts.KeyDataFormatPem)
    ctx.key.name = 'rsakey.pem'
    assert "rsakey.pem" == ctx.key.name

    ctx.sign(sign)
    assert load_xml("sign4-out.xml") == root

def test_sign_case5():
    """Should sign a file using a dynamicaly created template, key from PEM file and an X509 certificate."""
    root = load_xml("sign5-in.xml")
    sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
    assert sign is not None
    root.append(sign)
    ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
    xmlsec.template.add_transform(ref, consts.TransformEnveloped)

    ki = xmlsec.template.ensure_key_info(sign)
    x509 = xmlsec.template.add_x509_data(ki)
    xmlsec.template.x509_data_add_subject_name(x509)
    xmlsec.template.x509_data_add_certificate(x509)
    xmlsec.template.x509_data_add_ski(x509)
    x509_issuer_serial = xmlsec.template.x509_data_add_issuer_serial(x509)
    xmlsec.template.x509_issuer_serial_add_issuer_name(x509_issuer_serial, 'Test Issuer')
    xmlsec.template.x509_issuer_serial_add_serial_number(x509_issuer_serial, '1')

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.load_cert_from_file(rsacert, consts.KeyDataFormatPem)
    ctx.key.name = 'rsakey.pem'
    assert "rsakey.pem" == ctx.key.name

    ctx.sign(sign)
    sign_out = load_xml("sign5-out.xml")
    sign_out_s = etree.tostring(sign_out)
    root_s = etree.tostring(root)
    assert sign_out_s == root_s, "{!r} != {!r}".format(sign_out_s, root_s)

def test_sign_binary():
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.name = 'rsakey.pem'
    assert "rsakey.pem" == ctx.key.name

    sign = ctx.sign_binary(load("sign6-in.bin"), consts.TransformRsaSha1)
    assert load("sign6-out.bin") == sign

def test_verify_case_1():
    check_verify(1)

def test_verify_case_2():
    check_verify(2)

def test_verify_case_3():
    check_verify(3)

def test_verify_case_4():
    check_verify(4)

def test_verify_case_5():
    check_verify(5)

def check_verify(i):
    root = load_xml("sign%d-out.xml" % i)
    xmlsec.tree.add_ids(root, ["ID"])
    sign = xmlsec.tree.find_node(root, consts.NodeSignature)
    assert sign is not None
    assert consts.NodeSignature == sign.tag.partition("}")[2]

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsapub, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.name = 'rsapub.pem'
    assert "rsapub.pem" == ctx.key.name
    ctx.verify(sign)

def test_validate_binary_sign():
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(rsakey, format=consts.KeyDataFormatPem)
    assert ctx.key is not None
    ctx.key.name = 'rsakey.pem'
    assert "rsakey.pem" == ctx.key.name

    ctx.verify_binary(load("sign6-in.bin"), consts.TransformRsaSha1, load("sign6-out.bin"))


def main():
    failures = 0

    xmlsec.init()
    try:
        for name in dir(sys.modules[__name__]):
            if name.startswith("test_"):
                print("Running {}".format(name))
                func = getattr(sys.modules[__name__], name)
                try:
                    func()
                except AssertionError:
                    print("Failed {}".format(name))
                    traceback.print_exc()
                    failures += 1
                finally:
                    xmlsec.shutdown()
                    xmlsec.init()
    finally:
        print("Finished. Failures: {}".format(failures))


if __name__ == "__main__":
    main()
