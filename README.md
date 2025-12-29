# Memory-encryption-v2

Memory Protection

Runtime process memory encryption using XOR.

## Build

```bash
cl /EHsc /O2 /std:c++17 main.cpp
```

## Usage

```cpp
#include "encryptor.h"

ProtectedValue val(100);
int x = val.get();
val.set(200);
```

## Components

- `SecureXOR` - polymorphic key engine
- `ProtectedValue<T>` - encrypted value storage
- `StackGuard` - return address protection
- `TLSProtector` - thread-local encryption

- 
## Features


- Runtime XOR encryption
- Dynamic key rotation
- Stack frame protection
- TLS encryption support

## Notes

For optimal performance compile with optimization flags.
