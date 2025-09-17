#pragma once

#include <array>
#include <vector>
#include <string>
#include <functional>
#include <unordered_map>
#include <cstdint>
#include <span>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

// Z3DS File Format Structures
struct Z3DSFileHeader {
    static constexpr std::array<u8, 4> EXPECTED_MAGIC = {'Z', '3', 'D', 'S'};
    static constexpr u8 EXPECTED_VERSION = 1;
    
    std::array<u8, 4> magic = EXPECTED_MAGIC;
    std::array<u8, 4> underlying_magic{};
    u8 version = EXPECTED_VERSION;
    u8 reserved = 0;
    u16 header_size = sizeof(Z3DSFileHeader);
    u32 metadata_size = 0;
    u64 compressed_size = 0;
    u64 uncompressed_size = 0;
};
static_assert(sizeof(Z3DSFileHeader) == 0x20, "Invalid Z3DSFileHeader size");

class Z3DSMetadata {
public:
    static constexpr u8 METADATA_VERSION = 1;
    
    Z3DSMetadata() = default;
    
    void Add(const std::string& name, const std::string& data);
    void Add(const std::string& name, const std::vector<u8>& data);
    std::vector<u8> AsBinary() const;
    
private:
    struct Item {
        enum Type : u8 {
            TYPE_END = 0,
            TYPE_BINARY = 1,
        };
        
        Type type{};
        u8 name_len{};
        u16 data_len{};
    };
    static_assert(sizeof(Item) == 4);
    
    std::unordered_map<std::string, std::vector<u8>> items;
};

// Progress callback type
using ProgressCallback = std::function<void(std::size_t, std::size_t)>;

// Main compression function
bool CompressZ3DSFile(const std::string& src_file, const std::string& dst_file,
                      const std::array<u8, 4>& underlying_magic, size_t frame_size,
                      ProgressCallback update_callback = nullptr,
                      const std::unordered_map<std::string, std::vector<u8>>& metadata = {});

// Utility functions
std::array<u8, 4> DetectFileMagic(const std::string& filename);
size_t GetDefaultFrameSize(const std::array<u8, 4>& magic);
std::string GetCurrentTimeISO();