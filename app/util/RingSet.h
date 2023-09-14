#ifndef RINGSET_H
#define RINGSET_H

#include <vector>
#include <algorithm>
#include "../crypto/util.h"

class RingSet {
public:
    RingSet(size_t capacity);

    bool insert(Nonce& nonce);

    bool contains(Nonce& nonce) ;

private:
    size_t m_capacity;
    std::vector<Nonce> m_buffer;
    size_t m_head = 0; // Index to insert the next element
    size_t m_setSize = 0; // Number of unique elements currently in the buffer
};

#endif // RINGSET_H
