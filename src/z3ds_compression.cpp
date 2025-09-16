#include "z3ds_compression.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <zstd.h>

// Simple hash function to replace XXH64 (compatible implementation)
static u64 SimpleHash64(const void* data, size_t len, u64 seed = 0) {
    const u8* p = static_cast<const u8*>(data);
    u64 h = seed + len;
    
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL; // FNV prime
    }
    
    return h;
}

// We'll implement seekable compression using standard ZSTD with custom framing
// This is a simplified version that creates seekable frames manually

// Add this constructor to handle vector input instead of span
Z3DSMetadata::Z3DSMetadata(const std::vector<u8>& source_data) {
    if (source_data.empty()) {
        return;
    }
    
    std::string buf(reinterpret_cast<const char*>(source_data.data()), source_data.size());
    std::istringstream in(buf, std::ios::binary);
    
    u8 version;
    in.read(reinterpret_cast<char*>(&version), sizeof(version));
    
    if (version != METADATA_VERSION) {
        return;
    }
    
    while (!in.eof()) {
        Item item;
        in.read(reinterpret_cast<char*>(&item), sizeof(Item));
        
        // If end item is reached, stop processing
        if (item.type == Item::TYPE_END) {
            break;
        }
        
        // Only binary type supported for now
        if (item.type != Item::TYPE_BINARY) {
            in.ignore(static_cast<std::streamsize>(item.name_len) + item.data_len);
            continue;
        }
        
        std::string name(item.name_len, '\0');
        std::vector<u8> data(item.data_len);
        in.read(name.data(), name.size());
        in.read(reinterpret_cast<char*>(data.data()), data.size());
        
        items.insert({std::move(name), std::move(data)});
    }
}

void Z3DSMetadata::Add(const std::string& name, const std::string& data) {
    items[name] = std::vector<u8>(data.begin(), data.end());
}

void Z3DSMetadata::Add(const std::string& name, const std::vector<u8>& data) {
    items[name] = data;
}

std::vector<u8> Z3DSMetadata::AsBinary() const {
    if (items.empty()) {
        return {};
    }
    
    std::ostringstream out(std::ios::binary);
    
    // Write version
    u8 version = METADATA_VERSION;
    out.write(reinterpret_cast<const char*>(&version), sizeof(version));
    
    // Write items
    for (const auto& [name, data] : items) {
        Item item{
            .type = Item::TYPE_BINARY,
            .name_len = static_cast<u8>(std::min<size_t>(0xFF, name.size())),
            .data_len = static_cast<u16>(std::min<size_t>(0xFFFF, data.size())),
        };
        
        out.write(reinterpret_cast<const char*>(&item), sizeof(item));
        out.write(name.data(), item.name_len);
        out.write(reinterpret_cast<const char*>(data.data()), item.data_len);
    }
    
    // Write end item
    Item end{};
    out.write(reinterpret_cast<const char*>(&end), sizeof(end));
    
    std::string out_str = out.str();
    return std::vector<u8>(out_str.begin(), out_str.end());
}

std::array<u8, 4> DetectFileMagic(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return {'U', 'N', 'K', 'N'}; // Unknown
    }
    
    // First check for 3DSX format (magic at start)
    std::array<u8, 4> magic{};
    file.read(reinterpret_cast<char*>(magic.data()), 4);
    
    if (file.gcount() >= 4) {
        if (magic == std::array<u8, 4>{'3', 'D', 'S', 'X'}) {
            return magic;
        }
    }
    
    // Check for NCCH format (CXI) - magic at offset 0x100
    file.seekg(0x100, std::ios::beg);
    file.read(reinterpret_cast<char*>(magic.data()), 4);
    
    if (file.gcount() >= 4) {
        if (magic == std::array<u8, 4>{'N', 'C', 'C', 'H'}) {
            return magic;
        }
        if (magic == std::array<u8, 4>{'N', 'C', 'S', 'D'}) {
            return magic;
        }
    }
    
    // Check for CIA files - they don't have a standard magic, try to detect by structure
    // CIA files start with a certificate chain, we can check for ASN.1 structure
    file.seekg(0x00, std::ios::beg);
    file.read(reinterpret_cast<char*>(magic.data()), 4);
    
    if (file.gcount() >= 4) {
        // CIA files often start with 0x30 (ASN.1 SEQUENCE) for certificate
        if (magic[0] == 0x30) {
            // Additional heuristic: check file extension
            std::string ext = filename.substr(filename.find_last_of('.'));
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".cia") {
                return {'N', 'C', 'S', 'D'}; // Treat CIA as NCSD for frame size purposes
            }
        }
    }
    
    return {'U', 'N', 'K', 'N'};
}

size_t GetDefaultFrameSize(const std::array<u8, 4>& magic) {
    // CIA and CCI files use larger frame size (32MB), others use 1MB
    if (magic == std::array<u8, 4>{'N', 'C', 'S', 'D'}) {
        return 32 * 1024 * 1024; // 32MB for CIA/CCI
    }
    return 1024 * 1024; // 1MB for CXI and 3DSX
}

std::string GetCurrentTimeISO() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::gmtime(&time_t);
    
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Proper seekable ZSTD compression implementation
class SeekableZSTDCompressor {
private:
    struct SeekEntry {
        u32 compressed_size;
        u32 decompressed_size;
        u32 checksum; // XXH64 lower 32 bits
    };
    
    std::ofstream& output;
    size_t frame_size;
    ZSTD_CCtx* cctx;
    std::vector<u8> frame_buffer;
    size_t current_frame_pos;
    u64 total_compressed;
    std::vector<SeekEntry> seek_entries;
    bool use_checksums;
    
public:
    SeekableZSTDCompressor(std::ofstream& out, size_t frame_sz, bool checksums = true) 
        : output(out), frame_size(frame_sz), current_frame_pos(0), total_compressed(0), use_checksums(checksums) {
        cctx = ZSTD_createCCtx();
        frame_buffer.reserve(frame_size);
        // Set compression level to fast for better performance
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, 3);
    }
    
    ~SeekableZSTDCompressor() {
        if (cctx) {
            ZSTD_freeCCtx(cctx);
        }
    }
    
    bool WriteData(const u8* data, size_t size) {
        size_t remaining = size;
        const u8* ptr = data;
        
        while (remaining > 0) {
            size_t to_copy = std::min(remaining, frame_size - current_frame_pos);
            
            // Add data to current frame buffer
            frame_buffer.insert(frame_buffer.end(), ptr, ptr + to_copy);
            current_frame_pos += to_copy;
            ptr += to_copy;
            remaining -= to_copy;
            
            // If frame is full, compress and write it
            if (current_frame_pos >= frame_size) {
                if (!FlushFrame()) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    bool Finish() {
        // Flush any remaining data
        if (!frame_buffer.empty()) {
            if (!FlushFrame()) {
                return false;
            }
        }
        
        // Write seek table as skippable frame
        return WriteSeekTable();
    }
    
    u64 GetTotalCompressed() const {
        return total_compressed;
    }
    
    size_t GetFrameCount() const {
        return seek_entries.size();
    }
    
private:
    bool FlushFrame() {
        if (frame_buffer.empty()) {
            return true;
        }
        
        // Calculate checksum if enabled
        u32 checksum = 0;
        if (use_checksums) {
            u64 hash = SimpleHash64(frame_buffer.data(), frame_buffer.size(), 0);
            checksum = static_cast<u32>(hash & 0xFFFFFFFF);
        }
        
        // Compress the frame
        size_t const compressed_bound = ZSTD_compressBound(frame_buffer.size());
        std::vector<u8> compressed_buffer(compressed_bound);
        
        size_t compressed_size = ZSTD_compressCCtx(cctx, 
            compressed_buffer.data(), compressed_buffer.size(),
            frame_buffer.data(), frame_buffer.size(),
            3); // Compression level 3
            
        if (ZSTD_isError(compressed_size)) {
            std::cerr << "Compression error: " << ZSTD_getErrorName(compressed_size) << std::endl;
            return false;
        }
        
        // Write compressed frame
        output.write(reinterpret_cast<const char*>(compressed_buffer.data()), compressed_size);
        if (!output.good()) {
            return false;
        }
        
        // Record seek entry
        SeekEntry entry{
            .compressed_size = static_cast<u32>(compressed_size),
            .decompressed_size = static_cast<u32>(frame_buffer.size()),
            .checksum = checksum
        };
        seek_entries.push_back(entry);
        
        total_compressed += compressed_size;
        
        // Reset frame buffer
        frame_buffer.clear();
        current_frame_pos = 0;
        
        return true;
    }
    
    bool WriteSeekTable() {
        if (seek_entries.empty()) {
            return true;
        }
        
        // Calculate seek table size
        size_t entry_size = use_checksums ? 12 : 8; // 4+4+4 or 4+4 bytes per entry
        size_t table_size = seek_entries.size() * entry_size + 9; // +9 for footer
        
        // Write skippable frame header
        u32 skippable_magic = 0x184D2A5E; // ZSTD skippable frame magic
        u32 frame_size = static_cast<u32>(table_size);
        
        output.write(reinterpret_cast<const char*>(&skippable_magic), 4);
        output.write(reinterpret_cast<const char*>(&frame_size), 4);
        
        // Write seek table entries
        for (const auto& entry : seek_entries) {
            output.write(reinterpret_cast<const char*>(&entry.compressed_size), 4);
            output.write(reinterpret_cast<const char*>(&entry.decompressed_size), 4);
            if (use_checksums) {
                output.write(reinterpret_cast<const char*>(&entry.checksum), 4);
            }
        }
        
        // Write seek table footer
        u32 num_frames = static_cast<u32>(seek_entries.size());
        u8 descriptor = use_checksums ? 0x80 : 0x00; // bit 7 = checksum flag
        u32 seekable_magic = 0x8F92EAB1; // Seekable ZSTD magic
        
        output.write(reinterpret_cast<const char*>(&num_frames), 4);
        output.write(reinterpret_cast<const char*>(&descriptor), 1);
        output.write(reinterpret_cast<const char*>(&seekable_magic), 4);
        
        if (!output.good()) {
            std::cerr << "Error writing seek table" << std::endl;
            return false;
        }
        
        total_compressed += 8 + table_size; // skippable frame header + table
        return true;
    }
};

bool CompressZ3DSFile(const std::string& src_file, const std::string& dst_file,
                      const std::array<u8, 4>& underlying_magic, size_t frame_size,
                      ProgressCallback update_callback,
                      const std::unordered_map<std::string, std::vector<u8>>& metadata) {
    
    // Open source file
    std::ifstream input(src_file, std::ios::binary);
    if (!input.is_open()) {
        std::cerr << "Error: Could not open source file: " << src_file << std::endl;
        return false;
    }
    
    // Get file size
    input.seekg(0, std::ios::end);
    u64 uncompressed_size = input.tellg();
    input.seekg(0, std::ios::beg);
    
    // Open output file
    std::ofstream output(dst_file, std::ios::binary);
    if (!output.is_open()) {
        std::cerr << "Error: Could not create output file: " << dst_file << std::endl;
        return false;
    }
    
    // Create Z3DS header
    Z3DSFileHeader header;
    header.underlying_magic = underlying_magic;
    header.uncompressed_size = uncompressed_size;
    
    // Create metadata
    Z3DSMetadata meta;
    meta.Add("compressor", "Z3DS CLI Tool v1.0");
    meta.Add("date", GetCurrentTimeISO());
    meta.Add("maxframesize", std::to_string(frame_size));
    
    // Add user metadata
    for (const auto& [key, value] : metadata) {
        meta.Add(key, value);
    }
    
    auto metadata_binary = meta.AsBinary();
    header.metadata_size = ((metadata_binary.size() + 15) / 16) * 16; // Align to 16 bytes
    
    // Write header (will be updated later with compressed size)
    size_t header_pos = output.tellp();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    
    // Write metadata
    output.write(reinterpret_cast<const char*>(metadata_binary.data()), metadata_binary.size());
    
    // Pad metadata to 16-byte boundary
    size_t padding = header.metadata_size - metadata_binary.size();
    std::vector<u8> pad(padding, 0);
    output.write(reinterpret_cast<const char*>(pad.data()), padding);
    
    // Start compression with proper seekable ZSTD format
    SeekableZSTDCompressor compressor(output, frame_size, true);
    
    // Compress file in chunks
    constexpr size_t BUFFER_SIZE = 64 * 1024; // 64KB buffer
    std::vector<u8> buffer(BUFFER_SIZE);
    size_t processed = 0;
    
    while (input.good() && processed < uncompressed_size) {
        size_t to_read = std::min(BUFFER_SIZE, static_cast<size_t>(uncompressed_size - processed));
        input.read(reinterpret_cast<char*>(buffer.data()), to_read);
        size_t read_size = input.gcount();
        
        if (read_size == 0) break;
        
        if (!compressor.WriteData(buffer.data(), read_size)) {
            std::cerr << "Error during compression" << std::endl;
            return false;
        }
        
        processed += read_size;
        
        if (update_callback) {
            update_callback(processed, uncompressed_size);
        }
    }
    
    // Finish compression
    if (!compressor.Finish()) {
        std::cerr << "Error finishing compression" << std::endl;
        return false;
    }
    
    // Update header with compressed size
    header.compressed_size = compressor.GetTotalCompressed();
    output.seekp(header_pos);
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    
    if (!output.good()) {
        std::cerr << "Error writing final header" << std::endl;
        return false;
    }
    
    std::cout << "\nCreated " << compressor.GetFrameCount() << " seekable frames" << std::endl;
    
    return true;
}