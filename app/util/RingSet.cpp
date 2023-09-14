#include "RingSet.h"
#include <cstring>
#include <cstring>

RingSet::RingSet(size_t capacity) : m_capacity(capacity), m_buffer(capacity), m_setSize(0) {}

bool RingSet::insert(Nonce& nonce){
if (std::find(m_buffer.begin(), m_buffer.end(), nonce) != m_buffer.end()){
        // Element already exists in the buffer, do not insert it again
        return false;
    }
    
    //m_buffer[m_head] = value;
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

/*
int main() {
    RingSet ringSet(5);

    ringSet.insert(1);
    ringSet.insert(2);
    ringSet.insert(3);

    std::cout << "Contains 2: " << std::boolalpha << ringSet.contains(2) << std::endl; // true
    std::cout << "Contains 4: " << std::boolalpha << ringSet.contains(4) << std::endl; // false

    ringSet.insert(4);
    ringSet.insert(5);

    std::cout << "Contains 1: " << std::boolalpha << ringSet.contains(1) << std::endl; // true
    std::cout << "Contains 3: " << std::boolalpha << ringSet.contains(3) << std::endl; // true
    std::cout << "Contains 6: " << std::boolalpha << ringSet.contains(6) << std::endl; // false

    return 0;
}
*/