# Example sizes
STACK_SIZE = 10*1024*1024  # 10 MB stack
HEAP_SIZE  = 1024*1024*1024  # 1 GB heap

# Assign base addresses
stack_base = 0x700000000000
heap_base  = 0x800000000000

stack_mem = bytearray(STACK_SIZE)
heap_mem  = bytearray(HEAP_SIZE)

# Memory read/write abstraction
def read_mem(addr, size):
    if image_base <= addr < image_base + len(image):
        off = addr - image_base
        return image[off:off+size]
    elif stack_base <= addr < stack_base + STACK_SIZE:
        off = addr - stack_base
        return stack_mem[off:off+size]
    elif heap_base <= addr < heap_base + HEAP_SIZE:
        off = addr - heap_base
        return heap_mem[off:off+size]
    else:
        raise Exception(f"Invalid memory read at 0x{addr:X}")

def write_mem(addr, data):
    if image_base <= addr < image_base + len(image):
        off = addr - image_base
        image[off:off+len(data)] = data
    elif stack_base <= addr < stack_base + STACK_SIZE:
        off = addr - stack_base
        stack_mem[off:off+len(data)] = data
    elif heap_base <= addr < heap_base + HEAP_SIZE:
        off = addr - heap_base
        heap_mem[off:off+len(data)] = data
    else:
        raise Exception(f"Invalid memory write at 0x{addr:X}")
