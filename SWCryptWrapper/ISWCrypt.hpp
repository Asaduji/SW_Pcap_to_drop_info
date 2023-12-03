#pragma once
#include <cstdint>

class ISWCrypt
{
public:
    inline static ISWCrypt* s_pSingleton = nullptr;

    virtual void Decrypt(uint8_t* packet, int32_t size, int32_t keyIndex) = 0;
    virtual void Destroy() = 0;
};