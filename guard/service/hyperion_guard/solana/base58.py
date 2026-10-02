"""
Pure-Python zero-dependency Base58 encoder and decoder for Solana addresses and payloads.
Uses the standard Bitcoin/Solana alphabet.
"""

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE = len(ALPHABET)
ALPHABET_MAP = {char: index for index, char in enumerate(ALPHABET)}

def b58encode(raw: bytes) -> str:
    """Encodes bytes into a Base58 string."""
    if not raw:
        return ""
    
    # Count leading zero bytes
    zeros = 0
    for byte in raw:
        if byte == 0:
            zeros += 1
        else:
            break
            
    # Convert big-endian bytes to integer
    num = int.from_bytes(raw, byteorder="big")
    
    # Base58 conversion
    encoded = []
    while num > 0:
        num, remainder = divmod(num, BASE)
        encoded.append(ALPHABET[remainder])
        
    return "1" * zeros + "".join(reversed(encoded))

def b58decode(s: str) -> bytes:
    """Decodes a Base58 string into bytes."""
    if not s:
        return b""
        
    zeros = 0
    for char in s:
        if char == "1":
            zeros += 1
        else:
            break
            
    num = 0
    for char in s:
        if char not in ALPHABET_MAP:
            raise ValueError(f"Invalid Base58 character: '{char}'")
        num = num * BASE + ALPHABET_MAP[char]
        
    # Convert int back to big-endian bytes
    num_bytes = (num.bit_length() + 7) // 8
    result = num.to_bytes(num_bytes, byteorder="big") if num_bytes > 0 else b""
    return b"\x00" * zeros + result
