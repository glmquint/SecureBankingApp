#include "RingSet.h"
#include <cstring>
#include <cstring>

RingSet::RingSet(size_t capacity) : m_capacity(capacity), m_buffer(capacity), m_setSize(0) {}

bool RingSet::insert(Nonce& nonce){
if (std::find(m_buffer.begin(), m_buffer.end(), nonce) != m_buffer.end()){
        // Element already exists in the buffer, do not insert it again
        return false;
    }
    
    std::memcpy(&m_buffer[m_head], &nonce, sizeof(Nonce));
    m_head = (m_head + 1) % m_capacity;
    if (m_setSize < m_capacity) {
        m_setSize++;
    }

    return true;
}

bool RingSet::contains(Nonce& nonce)  {
    return std::find(m_buffer.begin(), m_buffer.begin() + m_setSize, nonce) != m_buffer.begin() + m_setSize;
}
