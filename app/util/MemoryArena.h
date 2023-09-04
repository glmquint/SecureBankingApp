#ifndef MEMARENA_H
#define MEMARENA_H
#include <cstddef>
#include <stdexcept>

class MemoryArena {
public:

    MemoryArena(std::size_t size);
    ~MemoryArena();
    void* allocate(std::size_t size);
    void deallocate(void* /*ptr*/);
private:
    char* m_memory;
    std::size_t m_size;
    std::size_t m_used;
};
#endif
