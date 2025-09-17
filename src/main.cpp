#include "z3ds_compression.h"
#include <iostream>
#include <filesystem>
#include <chrono>

void showUsage(const char* program_name) {
    std::cout << "Z3DS ROM Compressor - CLI Version\n";
    std::cout << "Based on Azahar Emulator's compression format\n\n";
    std::cout << "Usage: " << program_name << " <input_rom> [output_file] [options]\n\n";
    std::cout << "Arguments:\n";
    std::cout << "  input_rom     Input ROM file (.cci, .cia, .cxi, .3dsx)\n";
    std::cout << "  output_file   Output Z3DS file (optional, auto-generated if not specified)\n\n";
    std::cout << "Options:\n";
    std::cout << "  --frame-size SIZE   Set compression frame size in bytes (default: auto)\n";
    std::cout << "  --help, -h          Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " game.cia\n";
    std::cout << "  " << program_name << " game.cci game_compressed.zcci\n";
    std::cout << "  " << program_name << " game.cia --frame-size 33554432\n";
}

std::string generateOutputFilename(const std::string& input_file) {
    std::filesystem::path input_path(input_file);
    std::string extension = input_path.extension().string();
    std::string base_name = input_path.stem().string();
    
    // Add 'z' prefix to extension for Z3DS format
    std::string z3ds_extension;
    if (extension == ".cia") {
        z3ds_extension = ".zcia";
    } else if (extension == ".cci") {
        z3ds_extension = ".zcci";
    } else if (extension == ".cxi") {
        z3ds_extension = ".zcxi";
    } else if (extension == ".3dsx") {
        z3ds_extension = ".z3dsx";
    } else {
        z3ds_extension = ".z3ds";
    }
    
    return input_path.parent_path() / (base_name + z3ds_extension);
}

void progressCallback(std::size_t processed, std::size_t total) {
    double percentage = (double)processed / total * 100.0;
    int bar_width = 50;
    int filled = (int)(percentage / 100.0 * bar_width);
    
    std::cout << "\rProgress: [";
    for (int i = 0; i < bar_width; ++i) {
        if (i < filled) {
            std::cout << "=";
        } else if (i == filled) {
            std::cout << ">";
        } else {
            std::cout << " ";
        }
    }
    std::cout << "] " << std::fixed << std::setprecision(1) << percentage << "% (" 
              << processed << "/" << total << " bytes)";
    std::cout.flush();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        showUsage(argv[0]);
        return 1;
    }
    
    std::string input_file;
    std::string output_file;
    size_t frame_size = 0; // 0 means auto-detect
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            showUsage(argv[0]);
            return 0;
        } else if (arg == "--frame-size") {
            if (i + 1 < argc) {
                frame_size = std::stoull(argv[++i]);
            } else {
                std::cerr << "Error: --frame-size requires a value\n";
                return 1;
            }
        } else if (input_file.empty()) {
            input_file = arg;
        } else if (output_file.empty()) {
            output_file = arg;
        } else {
            std::cerr << "Error: Too many arguments\n";
            showUsage(argv[0]);
            return 1;
        }
    }
    
    if (input_file.empty()) {
        std::cerr << "Error: No input file specified\n";
        showUsage(argv[0]);
        return 1;
    }
    
    // Check if input file exists
    if (!std::filesystem::exists(input_file)) {
        std::cerr << "Error: Input file does not exist: " << input_file << std::endl;
        return 1;
    }
    
    // Generate output filename if not provided
    if (output_file.empty()) {
        output_file = generateOutputFilename(input_file);
    }
    
    // Detect file magic
    auto magic = DetectFileMagic(input_file);
    std::cout << "Detected file magic: " 
              << static_cast<char>(magic[0]) << static_cast<char>(magic[1])
              << static_cast<char>(magic[2]) << static_cast<char>(magic[3]) << std::endl;
    
    // Use auto frame size if not specified
    if (frame_size == 0) {
        frame_size = GetDefaultFrameSize(magic);
    }
    
    std::cout << "Using frame size: " << frame_size << " bytes (" 
              << (frame_size / 1024 / 1024) << " MB)" << std::endl;
    
    std::cout << "Compressing: " << input_file << std::endl;
    std::cout << "Output: " << output_file << std::endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Perform compression
    bool success = CompressZ3DSFile(input_file, output_file, magic, frame_size, progressCallback);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << std::endl; // New line after progress bar
    
    if (success) {
        // Calculate compression ratio
        auto input_size = std::filesystem::file_size(input_file);
        auto output_size = std::filesystem::file_size(output_file);
        double ratio = (double)output_size / input_size * 100.0;
        
        std::cout << "Compression completed successfully!" << std::endl;
        std::cout << "Original size: " << input_size << " bytes" << std::endl;
        std::cout << "Compressed size: " << output_size << " bytes" << std::endl;
        std::cout << "Compression ratio: " << std::fixed << std::setprecision(1) 
                  << ratio << "%" << std::endl;
        std::cout << "Time taken: " << duration.count() << " ms" << std::endl;
        return 0;
    } else {
        std::cerr << "Compression failed!" << std::endl;
        return 1;
    }
}