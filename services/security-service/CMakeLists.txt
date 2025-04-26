cmake_minimum_required(VERSION 3.16)

project(security-service VERSION 0.1.0 LANGUAGES CXX)

# --- Proto Configuration ---

# Root directories for protoc include paths (-I)
set(PROTO_INCLUDE_ROOTS
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/envoy/api" # Adjusted path
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/googleapis"
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/xds"
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/validate"
    # We will also need the Protobuf include directory from vcpkg later
)

# Find all .proto files within the source directories - Use explicit globs
file(GLOB_RECURSE ALL_PROTO_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/envoy/*.proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/googleapis/*.proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/xds/*.proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/protos/validate/*.proto"
)
list(LENGTH ALL_PROTO_FILES _num_proto_files)
message(STATUS "Found ${_num_proto_files} total proto files using GLOB_RECURSE.")


# Define the output directory for generated files (within the build tree)
set(PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-protos")
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

# Also add the generated directory itself as an include root for protoc
list(APPEND PROTO_INCLUDE_ROOTS ${PROTO_GEN_DIR})

# --- End Proto Configuration ---

# Find the Protobuf package provided by vcpkg
find_package(Protobuf CONFIG REQUIRED)

# Get the include directory from the found Protobuf package
get_target_property(PROTOBUF_INCLUDE_DIR protobuf::libprotobuf INTERFACE_INCLUDE_DIRECTORIES)
list(APPEND PROTO_INCLUDE_ROOTS ${PROTOBUF_INCLUDE_DIR})
message(STATUS "Protobuf include dir (from vcpkg): ${PROTOBUF_INCLUDE_DIR}")


# Find the gRPC package provided by vcpkg
find_package(gRPC CONFIG REQUIRED)

# Explicitly find the gRPC C++ plugin executable installed by vcpkg
# It's often installed in the 'tools' directory relative to the package.
find_program(gRPC_CPP_PLUGIN_EXECUTABLE_FOUND grpc_cpp_plugin
    HINTS "${CMAKE_CURRENT_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/tools/grpc"
    NO_DEFAULT_PATH
)
if(NOT gRPC_CPP_PLUGIN_EXECUTABLE_FOUND)
    # Try searching system paths as a fallback (less likely with vcpkg)
    find_program(gRPC_CPP_PLUGIN_EXECUTABLE_FOUND grpc_cpp_plugin)
endif()

if(NOT gRPC_CPP_PLUGIN_EXECUTABLE_FOUND)
    message(FATAL_ERROR "Could not find grpc_cpp_plugin executable. Check vcpkg installation.")
else()
    set(gRPC_CPP_PLUGIN_EXECUTABLE ${gRPC_CPP_PLUGIN_EXECUTABLE_FOUND}) # Set the variable correctly
    message(STATUS "Found gRPC Plugin Executable: ${gRPC_CPP_PLUGIN_EXECUTABLE}")
endif()

# DEBUG: Check the gRPC plugin path (Original message kept for verification)
# message(STATUS "gRPC Plugin Executable (from vcpkg find_package): ${gRPC_CPP_PLUGIN_EXECUTABLE}")


# --- Proto Generation ---

# Construct the include path arguments for protoc
set(PROTO_INCLUDE_ARGS "")
foreach(include_root ${PROTO_INCLUDE_ROOTS})
    list(APPEND PROTO_INCLUDE_ARGS -I ${include_root})
endforeach()
message(STATUS "Protoc include args: ${PROTO_INCLUDE_ARGS}")

# Prepare lists to hold unique generation targets
set(PROTO_UNIQUE_OUTPUT_HEADERS "")
set(PROTO_UNIQUE_OUTPUT_SOURCES "")
# NEW Parallel lists:
set(PROTO_FILES_TO_GENERATE "")     # Store the actual proto file paths
set(PROTO_GEN_DIRS_FOR_FILES "")    # Store the corresponding generation directory (currently always PROTO_GEN_DIR)
set(_processed_outputs "")          # Helper to track processed output files

# Loop 1: Identify unique proto outputs to avoid duplicate rules
message(STATUS "Identifying unique proto outputs...")
foreach(proto_file ${ALL_PROTO_FILES})
    set(relative_path "")
    set(_reversed_roots ${PROTO_INCLUDE_ROOTS}) # Create a copy
    list(REVERSE _reversed_roots)              # Reverse the copy
    foreach(include_root ${_reversed_roots})   # Iterate over the reversed copy
        string(REGEX REPLACE "([.^$*+?()|{}\\[\\]])" "\\\\\\1" escaped_root ${include_root})
        if(proto_file MATCHES "^${escaped_root}/(.*)")
            set(relative_path ${CMAKE_MATCH_1})
            break()
        endif()
    endforeach()

    # Check handling for files directly in include roots (e.g., validate.proto)
    if(relative_path STREQUAL "")
        foreach(include_root ${PROTO_INCLUDE_ROOTS})
             # Check if it's directly inside an include root dir
             get_filename_component(proto_dir ${proto_file} DIRECTORY)
             if("${proto_dir}" STREQUAL "${include_root}")
                  get_filename_component(relative_path ${proto_file} NAME)
                  break()
             endif()
        endforeach()
    endif()

    if(relative_path STREQUAL "") # If still empty after checks
        # message(WARNING "Could not determine relative path for proto: ${proto_file}. Skipping.")
        continue()
    endif()

    string(REGEX REPLACE "\\.proto$" "" basename ${relative_path})
    set(output_base "${PROTO_GEN_DIR}/${basename}")
    set(cpp_out "${output_base}.pb.cc")
    set(h_out "${output_base}.pb.h")
    set(grpc_cpp_out "${output_base}.grpc.pb.cc")
    set(grpc_h_out "${output_base}.grpc.pb.h")

    set(output_key "${cpp_out};${h_out};${grpc_cpp_out};${grpc_h_out}")
    list(FIND _processed_outputs "${output_key}" _found_index)

    if(_found_index EQUAL -1)
        list(APPEND _processed_outputs "${output_key}")
        list(APPEND PROTO_UNIQUE_OUTPUT_HEADERS ${h_out} ${grpc_h_out})
        list(APPEND PROTO_UNIQUE_OUTPUT_SOURCES ${cpp_out} ${grpc_cpp_out})
        list(APPEND PROTO_FILES_TO_GENERATE ${proto_file})
        list(APPEND PROTO_GEN_DIRS_FOR_FILES ${PROTO_GEN_DIR})
    endif()
endforeach()
list(LENGTH PROTO_FILES_TO_GENERATE _num_unique_protos)
message(STATUS "Identified ${_num_unique_protos} unique proto outputs to generate.")


# Loop 2: Generate the custom commands using indexed access to parallel lists
message(STATUS "Generating custom commands for ${_num_unique_protos} protos...")
if(_num_unique_protos GREATER 0)
  math(EXPR _last_idx "${_num_unique_protos} - 1") # Calculate last index for loop
  foreach(idx RANGE ${_last_idx})
      list(GET PROTO_FILES_TO_GENERATE ${idx} proto_file)
      list(GET PROTO_GEN_DIRS_FOR_FILES ${idx} gen_dir)

      set(relative_path "")
      set(_reversed_roots ${PROTO_INCLUDE_ROOTS}) # Create a copy
      list(REVERSE _reversed_roots)              # Reverse the copy
      foreach(include_root ${_reversed_roots})   # Iterate over the reversed copy
           string(REGEX REPLACE "([.^$*+?()|{}\\[\\]])" "\\\\\\1" escaped_root ${include_root})
          if(proto_file MATCHES "^${escaped_root}/(.*)")
              set(relative_path ${CMAKE_MATCH_1})
              break()
          endif()
      endforeach()

      # Add check for files directly in include roots (e.g., validate.proto)
      if(relative_path STREQUAL "")
          foreach(include_root ${PROTO_INCLUDE_ROOTS})
               # Check if it's directly inside an include root dir
               get_filename_component(proto_dir ${proto_file} DIRECTORY)
               if("${proto_dir}" STREQUAL "${include_root}")
                    get_filename_component(relative_path ${proto_file} NAME)
                    break()
               endif()
          endforeach()
      endif()

      if(relative_path STREQUAL "")
          message(FATAL_ERROR "Failed to recalculate relative path for ${proto_file} in Loop 2.")
          continue()
      endif()

      string(REGEX REPLACE "\\.proto$" "" basename ${relative_path})
      set(output_base "${gen_dir}/${basename}")
      set(cpp_out "${output_base}.pb.cc")
      set(h_out "${output_base}.pb.h")
      set(grpc_cpp_out "${output_base}.grpc.pb.cc")
      set(grpc_h_out "${output_base}.grpc.pb.h")

      # Use the explicitly found plugin path
      add_custom_command(
          OUTPUT ${cpp_out} ${h_out} ${grpc_cpp_out} ${grpc_h_out}
          COMMAND ${CMAKE_COMMAND} -E make_directory "${gen_dir}/${basename}/.."
          COMMAND ${Protobuf_PROTOC_EXECUTABLE}
              ${PROTO_INCLUDE_ARGS}
              --cpp_out=${gen_dir}
              --grpc_out=${gen_dir}
              --plugin=protoc-gen-grpc=${gRPC_CPP_PLUGIN_EXECUTABLE} # Uses explicitly set variable
              ${proto_file}
          DEPENDS ${proto_file} ${Protobuf_PROTOC_EXECUTABLE} ${gRPC_CPP_PLUGIN_EXECUTABLE}
          COMMENT "Generating C++ sources from ${proto_file}"
          VERBATIM
      )
  endforeach()
endif()
message(STATUS "Finished generating custom commands.")

# Create a static library from the generated source files
add_library(generated_protos STATIC ${PROTO_UNIQUE_OUTPUT_SOURCES})

# Ensure the compiler can find the generated headers and standard protobuf headers
target_include_directories(generated_protos PUBLIC
    ${PROTO_GEN_DIR}          # Directory containing *.pb.h, *.grpc.pb.h
    ${PROTOBUF_INCLUDE_DIR} # Directory containing google/protobuf/*.h
)

# --- End Proto Generation ---

add_executable(security-service src/main.cc)

# Link our executable against Protobuf and gRPC libraries AND our generated code
target_link_libraries(security-service PRIVATE
    generated_protos      # Link against our generated code library
    protobuf::libprotobuf # Link against core protobuf runtime
    gRPC::grpc++          # Link against core gRPC runtime
)
