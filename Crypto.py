# Importing necessary modules from cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import OCSPRequestBuilder
import os
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.backends import default_backend
from cryptography import x509
# Importing necessary modules from ecdsa
from ecdsa import VerifyingKey, curves, NIST256p, NIST384p, NIST521p, ellipticcurve, numbertheory
from ecdsa.util import sigdecode_der

# Other necessary standard library imports
from datetime import datetime
import hashlib
import argparse

crl_cache = {}






from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
# Function to load a certificate from a file
def load_certificate(file_path, file_format):

    with open(file_path, "rb") as file:
        if file_format == 'PEM':
            cert = x509.load_pem_x509_certificate(file.read(), default_backend())
        elif file_format == 'DER':
            cert = x509.load_der_x509_certificate(file.read(), default_backend())
        else:
            raise ValueError('Unsupported format. Please use DER or PEM.')
    print("👌 Certificate loaded. 👌")
    return cert

# Function to get information from a certificate
def get_certificate_info(cert):
    print("⏱️ Getting certificate info... ⏱️")
    subject = cert.subject
    issuer = cert.issuer
    public_key = cert.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("👌 Certificate info obtained. 👌")
    print("   ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️")
    print("-----------------------------------------------------------------------------------------------------------------------------------------------------------")
    return subject, issuer, public_key_pem

# Function to verify the key usage of a certificate
def verify_key_usage(cert):
    print("-----------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("⏱️ Verifying key usage... ⏱️")
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        print("✅ Key usage verified. ✅")
        return key_usage
    except x509.ExtensionNotFound:
        print("❌ Key usage extension not found. ❌")
        return None

def verify_via_OCSP(cert, issuer_cert):
    # Get the Authority Information Access extension
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        print("Authority Information Access extension not found. Assuming root certificate is valid.")
       
        return

    # Find the OCSP server URL
    ocsp_url = None
    for access_description in aia.value:
        if access_description.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_url = access_description.access_location.value

    if ocsp_url is None:
        print("❌OCSP server URL not found.❌")
        return

    # Create an OCSP request
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
    req = builder.build()

    # Send the OCSP request
    response = requests.post(ocsp_url, data=req.public_bytes(serialization.Encoding.DER))

    # Parse the OCSP response
    ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)

    # Check the revocation status
    if ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED:
        print("❌OCSP   Certificate has been revoked.❌")
    else:
        print("OCSP  ⏱️⏱️ Certificate has not been revoked.  ⏱️")
# Function to verify the validity period of a certificate
def verify_validity_period(cert):
    print("⏱️ Verifying validity period... ⏱️")
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    current_time = datetime.utcnow()
    if current_time < not_before or current_time > not_after:
        print("❌ Validity period verification failed. ❌")
        
    else: 
        print("✅ Validity period verified. ✅")
    try:
        print("verifying the revocation status of the certificate")
        crl_dist_points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        print("CRL Distribution Points extension not found.")
        return

    for dist_point in crl_dist_points.value:
        for url in dist_point.full_name:
       

            crl = download_crl_if_updated(url.value)

            if crl is None:
                print("CRL has not been updated.")
                continue

            # Check if the certificate is in the CRL
            for revoked_cert in crl:
                if revoked_cert.serial_number == cert.serial_number:
                    print("Certificate has been revoked.")
                    return

        print("Certificate has not been revoked.")


def download_crl_if_updated(distribution_point):
    print("⏱️ Downloading CRL... ⏱️")

    # Get the last update date from the cache
    last_update = crl_cache.get(distribution_point)

    # Download the CRL
    response = requests.get(distribution_point)
    content = response.content

    # Determine the format (PEM or DER)
    if content.startswith(b'-----BEGIN'):
        # PEM format
        crl = x509.load_pem_x509_crl(content, default_backend())
    else:
        # DER format
        crl = x509.load_der_x509_crl(content, default_backend())

    # If the CRL has not been updated, return None
    if last_update is not None and crl.last_update <= last_update:
        print("✅✅✅ CRL has not been updated. ✅✅✅")
        return None

    # Update the cache
    crl_cache[distribution_point] = crl.last_update
    
    return crl

def verify_basic_constraints(cert):
    try:
        # Get the BasicConstraints extension
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)

        # Check if the extension is critical
        if basic_constraints.critical:
            print("✅ BasicConstraints extension is present and marked as critical. ✅")
        else:
            print("⚠️ BasicConstraints extension is present but not marked as critical. ⚠️")
    except x509.ExtensionNotFound:
        print("❌ BasicConstraints extension is not present. ❌")
# Function to extract signature algorithm and verify signature

# Function to validate a certificate
def validate_certificate(file_path, file_format):
    print("⏱️ Validating certificate... ⏱️")
    cert = load_certificate(file_path, file_format)
    subject, issuer, public_key_pem = get_certificate_info(cert)
    print(f'Subject: {subject}') 
    print(f'Issuer: {issuer}')
    print(f'Public Key: {public_key_pem}')

    key_usage = verify_key_usage(cert)
    if key_usage is not None:
        print(f'Key Usage: {key_usage}')

    if verify_validity_period(cert):
        print('========== ✅ The certificate is currently valid. ✅ ==========')
    else:
        print('========== ❌ The certificate is not currently valid. ❌ ==========')

    extract_and_verify_signature(cert)

    print("✨ Certificate validation completed. ✨")

def validate_certificate_chain(file_paths, file_format):
    print("Validating certificate chain...")
    previous_cert = None
    for file_path in file_paths:
        cert = load_certificate(file_path, file_format)
        subject, issuer, public_key_pem = get_certificate_info(cert)
        print(f'| Subject: {subject} |')
        print(f'| Issuer: {issuer} |')
        print(f'| Public Key: {public_key_pem} |')
        print(f"| File format: {file_format} |")

        key_usage = verify_key_usage(cert)
        if key_usage is not None:
            print(f'Key Usage: {key_usage}')
        verify_basic_constraints(cert)
        verify_validity_period(cert)
        
    

        if previous_cert is not None:
            verify_via_OCSP(cert, previous_cert)
            extract_and_verify_signature(cert, previous_cert.public_key()) #valide la signature avec les .verify 
            extract_and_verify_signature2(cert, previous_cert.public_key()) #valide la signature mathematiquement 

        else:
            verify_via_OCSP(cert, None)
            extract_and_verify_signature(cert, None)

        previous_cert = cert

    print("========== ✨ Certificate chain validation completed. ✨ ==========")

# Créer un parseur d'arguments



def extract_and_verify_signature(cert,parent_public_key):
    print("⏱️ Extracting signature algorithm... ⏱️")
    print("   ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️ ⬇️")
    signature_algorithm_oid = cert.signature_algorithm_oid
    print(f'➡️ Signature Algorithm: {signature_algorithm_oid}')

    print("⏱️ Verifying signature... ⏱️")
    print("...")
    print("...")
    if parent_public_key is None:
        # Si aucune clé publique parente n'est fournie, utilisez la clé publique du certificat lui-même
        public_key = cert.public_key()
    else:
        public_key = parent_public_key
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            print("⏱️ Verifying RSA signature... ⏱️")
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            print("✅ Signature RSA verified. ✅")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            print("⏱️ Verifying ECDSA signature... ⏱️")
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            print("✅ Signature ECDSA verified. ✅")
    except InvalidSignature:
        print("❌ Signature verification failed. ❌")

def extract_and_verify_signature2(cert,parent_public_key):
    print("⏱️ Extracting signature algorithm... ⏱️")
    print("   ⏱️⏱️⏱️⏱️⏱️⏱️⏱️⏱️⏱️⏱️⏱️⏱️")
    signature_algorithm_oid = cert.signature_algorithm_oid
    print(f'➡️ Signature Algorithm: {signature_algorithm_oid}')

    print("⏱️ Verifying signature... ⏱️")
    print("...")
    print("...")
    if parent_public_key is None:
        # Si aucune clé publique parente n'est fournie, utilisez la clé publique du certificat lui-même
        public_key = cert.public_key()
    else:
        public_key = parent_public_key
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            print("⏱️ Verifying RSA signature mathematically... ⏱️")
            # Convertir la signature en entier
            signature_int = int.from_bytes(cert.signature, byteorder='big')

            # Récupérer l'exposant public et le module depuis la clé publique
            public_numbers = public_key.public_numbers()
            e = public_numbers.e
            n = public_numbers.n

            # "Déchiffrer" la signature en utilisant l'exposant public et le module
            decrypted_signature_int = pow(signature_int, e, n)

            # Convertir le résultat en bytes
            decrypted_signature_bytes = decrypted_signature_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

            # Calculer le hash attendu des données TBS
            hash_algorithm = cert.signature_hash_algorithm.name.upper()
            if hash_algorithm == 'SHA256':
                expected_hash = hashlib.sha256(cert.tbs_certificate_bytes).digest()
            elif hash_algorithm == 'SHA1':
                expected_hash = hashlib.sha1(cert.tbs_certificate_bytes).digest()
            # Ajoutez d'autres algorithmes de hashage si nécessaire

            # Comparer le hash extrait avec le hash attendu
            if decrypted_signature_bytes.endswith(expected_hash):
                print("✅ Signature RSA mathematically verified. ✅")
            else:
                print("❌ Mathematical RSA signature verification failed. ❌")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            parent_public_key = public_key
            parent_public_numbers = public_key.public_numbers()
            # Convertir la clé publique du parent en format compatible ecdsa
            curve_name = public_key.curve.name

            # Faites le mapping entre le nom de la courbe de 'cryptography' et les objets de courbe dans 'ecdsa'
            curve_mapping = {
                'secp256r1': curves.NIST256p,
                'secp384r1': curves.NIST384p,
                'secp521r1': curves.NIST521p,
                # Ajoutez d'autres mappings de courbes ici si nécessaire
            }

            # Trouvez l'objet de courbe ECDSA correspondant
            ecdsa_curve = curve_mapping.get(curve_name.lower())
            if ecdsa_curve is None:
                raise ValueError(f"Unsupported curve: {curve_name}")
            
            generator = ecdsa_curve.generator
            
            parent_public_key_ecdsa = VerifyingKey.from_public_point(
                ellipticcurve.Point(ecdsa_curve.curve, parent_public_numbers.x, parent_public_numbers.y),
                curve=ecdsa_curve
            )

                        # Extraire la signature du certificat enfant
            signature = cert.signature

            # Décodage de la signature
            r, s = sigdecode_der(signature, ecdsa_curve.order)

            # Calcul du hash des données signées
            hash_algorithm = cert.signature_hash_algorithm.name
            hash_func = getattr(hashlib, hash_algorithm)
            hashed_tbs = hash_func(cert.tbs_certificate_bytes).digest()

            # Effectuer la vérification mathématique de la signature
            order = ecdsa_curve.order
            w = numbertheory.inverse_mod(s, order)
            u1 = (int.from_bytes(hashed_tbs, 'big') * w) % order
            u2 = (r * w) % order
            point = u1 * generator + u2 * parent_public_key_ecdsa.pubkey.point
            if point.x() % order == r:
                print("Signature is valid, verification par les courbes.")
            else:
                print("Signature is invalid.")
    except Exception as e:
                print("Signature is invalid:", e)


# Main function
if __name__ == "__main__":
    # Parsing command line arguments
    parser = argparse.ArgumentParser(description='Validate a certificate or a certificate chain.')
    parser.add_argument('file_format', type=str, choices=['PEM', 'DER'], help='The format of the certificate files.')
    parser.add_argument('file_paths', type=str, nargs='+', help='The paths to the certificate files, in order.')
    parser.add_argument('--chain', action='store_true', help='Validate a certificate chain instead of a single certificate.')
    args = parser.parse_args()

    # Validating the certificate or the certificate chain
    if args.chain:
        validate_certificate_chain(args.file_paths, args.file_format) 
        
    else:
        if len(args.file_paths) != 1:
            print("Please provide exactly one file path when validating a single certificate.")
        else:
            validate_certificate(args.file_paths[0], args.file_format)
