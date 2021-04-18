# Text files encryption using strategy design pattern in C++.

This source code is a template of using the **strategy** design pattern for text files encryption in C++.  
This project is a homework from my college programming teacher.

## Problem statement:

> Develop the program for encrypting text documents.  
> The user enters a string containing the path to the text file ("C:/example.txt").  
> After that, he enters a number from 1 to 3 to clarify the text encryption method.  
> After the selected algorithm works, the encrypted text is saved to another file ("C:/example_ciphered.txt").  
> Develop the console application that implements the described functionality and contains a hierarchy of encryption classes.  
> Justify the selected class hierarchy and the selected design pattern.

## Implementation:

A basic virtual class for std::string encryption strategies:

```cpp
class EncryptionStrategy
{
public:
    virtual std::string encrypt(const std::string &text, const std::string &key = "") = 0;
    virtual std::string decrypt(const std::string &text, const std::string &key = "") = 0;
};
```

Concrete encryption strategy using XOR:

```cpp
class XOREncryptionStrategy : public EncryptionStrategy ...
```

Concrete encryption strategy using Caesar:

```cpp
class CaesarEncryptionStrategy : public EncryptionStrategy ...
```

Concrete encryption strategy using Binary code:

```cpp
class BinaryEncryptionStrategy : public EncryptionStrategy ...
```

Interface for file encryption using encryption strategies:

```cpp
class IFileEncryptor ...
```
