"""Support signature verification."""

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_verifier(context, img_signature_certificate_uuid,
                 img_signature_hash_method, img_signature,
                 img_signature_key_type):
    """Instantiate signature properties and use them to create a verifier.

    :param context: the user context for authentication
    :param img_signature_certificate_uuid:
           uuid of signing certificate stored in key manager
    :param img_signature_hash_method:
           string denoting hash method used to compute signature
    :param img_signature: string of base64 encoding of signature
    :param img_signature_key_type:
           string denoting type of keypair used to compute signature
    :returns: instance of
       cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext
    :raises: SignatureVerificationError if we fail to build the verifier
    """
    raise NotImplemented()
