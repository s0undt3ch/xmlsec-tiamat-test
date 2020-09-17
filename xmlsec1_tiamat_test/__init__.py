import os
import sys
import lxml
import xmlsec
import pathlib
from lxml import etree


consts = xmlsec.constants


PKG_DIR = pathlib.Path(getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))).resolve()
DATA_DIR = PKG_DIR / "data"
import pprint
pprint.pprint(os.listdir(str(PKG_DIR)))
rsacert = str(DATA_DIR / "rsacert.pem")


def load_xml(name, xpath=None):
    """returns xml.etree"""
    root = etree.parse(str(DATA_DIR / name)).getroot()
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


def main():
    print("Running test_encrypt_xml")
    test_encrypt_xml()
    print("Finished")


if __name__ == "__main__":
    main()
