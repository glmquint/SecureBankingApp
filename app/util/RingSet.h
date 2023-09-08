#ifndef RINGSET_H
#define RINGSET_H

#include <vector>
#include <algorithm>

template <typename T>
class RingSet {
public:
    RingSet(size_t capacity);

    bool insert(const T& value);

    bool contains(const T& value) const;

private:
    size_t m_capacity;
    std::vector<T> m_buffer;
    size_t m_head = 0; // Index to insert the next element
    size_t m_setSize = 0; // Number of unique elements currently in the buffer
};

#endif // RINGSET_H
