from nacl.encoding import HexEncoder
from nacl.encoding import Base64Encoder
from nacl.signing import VerifyKey
"""
This Python code can be used to verify messages signed by: https://asecuritysite.com/signatures/gocred

However, for gocred, we need to acquire a base64 version of the credential message for verification purposes. See the updated 'gocred' code below to obtain this value:
https://replit.com/@owenlo/gocred#main.go

Run the above gocred code and replace the below variables (public key, proof signature and base64 credential output) to verify a message. Example values have been provided which should produce a valid proof.
"""

PublicKey = "627f86ef961962eec3951854ce0764aa8f458fd59f987bd7928609744de05994"
SignatureProof = "f6b7f37c1abeadab1a3831f63efa3d570d3700f03e58c18b13d69c7b18d95af49bc1ee4fb56740d2ef239516eb244cc41be9332cb8d540ab4b4fe0d5c35e2201"
Message = "e1todHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSBodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy9leGFtcGxlcy92MV0gZGlkOmV4YW1wbGU6MTIzI293bmVyIFtWZXJpZmlhYmxlQ3JlZGVudGlhbCBVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbF0gaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSB7MTM4NjgyOTI1ODE5MTQ0NzUzMjkgMTc4NjAxIDB4NThhZGUwfSB7ZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIEZyZWQgU21pdGggQWNoZWxvdXMgVW5pdmVyc2l0eSBTY2hvb2wgb2YgV2luZHMgYW5kIEFpciBQaER9IHsgezAgMCA8bmlsPn0gW10gW119fQ=="

# Create a VerifyKey object from a hex serialized public key
verify_key = VerifyKey(
    PublicKey,
    encoder=HexEncoder)

# Check the validity of a message's signature
signature_bytes = HexEncoder.decode(
    SignatureProof
)

try:
  #If verification fails, an exception is raised. Otherwise, the verification is deemed successful.
  verify_key.verify(Message, signature_bytes, encoder=Base64Encoder)
  print("Valid Proof!")
except:
  print("Invalid Proof! ")