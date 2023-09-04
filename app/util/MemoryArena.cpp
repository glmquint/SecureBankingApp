#include "MemoryArena.h"
#include <iostream>

MemoryArena::MemoryArena(std::size_t size) : m_size(size), m_used(0) {
    std::cout << "Btw, you're still using MemoryArena" << std::endl;
    m_memory = new char[size];
}

MemoryArena::~MemoryArena() {
    delete[] m_memory;
}

void* MemoryArena::allocate(std::size_t size) {
    if (m_used + size <= m_size) {
        void* ptr = m_memory + m_used;
        m_used += size;
        return ptr;
    } else {
        throw std::bad_alloc();
    }
}

void MemoryArena::deallocate(void* /*ptr*/) {
    // Memory arena doesn't support individual deallocation
    // All memory is released when the arena is destructed
}

/*
int main() {
    try {
        MemoryArena arena(1024); // Create a memory arena with 1024 bytes

        int* intPtr = static_cast<int*>(arena.allocate(sizeof(int))); // Allocate space for an int
        *intPtr = 42;

        // You can allocate other types as well
        double* doublePtr = static_cast<double*>(arena.allocate(sizeof(double)));
        *doublePtr = 3.14;

        // Note: No need to deallocate individual blocks, it's handled by the arena

        // When the arena goes out of scope, all memory will be released

    } catch (const std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
    }

    return 0;
}
*/