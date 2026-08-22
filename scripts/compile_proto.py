import os
import sys
import subprocess

def compile_protobufs():
    print("Orchestrating Protobuf compilation...")
    
    # Resolve paths
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proto_dir = os.path.join(base_dir, "shared", "proto")
    output_dir = os.path.join(base_dir, "shared", "proto") # output python bindings in the same place
    
    print(f"Base Directory: {base_dir}")
    print(f"Proto Directory: {proto_dir}")
    
    proto_files = [
        "common.proto",
        "flow.proto",
        "device.proto",
        "alerts.proto",
        "handshake.proto",
        "health.proto"
    ]
    
    # Try importing grpc_tools.protoc first
    try:
        from grpc_tools import protoc
        print("Using Python grpc_tools.protoc to compile...")
        
        for proto in proto_files:
            proto_path = os.path.join(proto_dir, proto)
            args = [
                "grpc_tools.protoc",
                f"-I{proto_dir}",
                f"--python_out={output_dir}",
                # Uncomment below if we need grpc services
                # f"--grpc_python_out={output_dir}",
                proto_path
            ]
            print(f"Compiling {proto}...")
            result = protoc.main(args)
            if result != 0:
                print(f"Error compiling {proto}. Exit code: {result}")
                sys.exit(1)
        print("Protobuf compilation completed successfully via grpc_tools!")
        
    except ImportError:
        # Fallback to standard protoc command line tool
        print("grpc_tools not found. Trying standard 'protoc' on PATH...")
        try:
            for proto in proto_files:
                proto_path = os.path.join(proto_dir, proto)
                cmd = [
                    "protoc",
                    f"-I={proto_dir}",
                    f"--python_out={output_dir}",
                    proto_path
                ]
                print(f"Running command: {' '.join(cmd)}")
                subprocess.check_call(cmd)
            print("Protobuf compilation completed successfully via standard protoc!")
        except subprocess.CalledProcessError as e:
            print(f"Error running standard protoc: {e}")
            if e.stderr:
                print(f"stderr: {e.stderr}")
            if e.stdout:
                print(f"stdout: {e.stdout}")
            print("Please install grpcio-tools in the environment:")
            print("  pip install grpcio-tools")
            sys.exit(1)
        except Exception as e:
            print(f"Error running standard protoc: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr)
            elif hasattr(e, 'output') and e.output:
                print(e.output.decode() if isinstance(e.output, bytes) else e.output)
            print("Please install grpcio-tools in the environment:")
            print("  pip install grpcio-tools")
            sys.exit(1)

if __name__ == "__main__":
    compile_protobufs()
