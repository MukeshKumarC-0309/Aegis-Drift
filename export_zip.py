import os
import zipfile

def create_export_zip(output_filename="SilentShift-Enterprise-Export.zip"):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(base_dir, output_filename)
    
    exclude_dirs = {'.git', '.pytest_cache', '__pycache__', '.venv', 'venv', 'env', '.idea', '.vscode'}
    exclude_extensions = {'.pyc', '.pyo', '.pyd', '.zip'}

    print(f"Creating clean export archive: {output_filename}...")
    file_count = 0

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(base_dir):
            # Modify dirs in-place to avoid recursing into excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file == output_filename:
                    continue
                _, ext = os.path.splitext(file)
                if ext in exclude_extensions:
                    continue
                
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, base_dir)
                zipf.write(full_path, rel_path)
                file_count += 1

    file_size_kb = os.path.getsize(output_path) / 1024
    print(f"Successfully packaged {file_count} files into '{output_filename}' ({file_size_kb:.1f} KB)")
    print(f"Export location: {output_path}")

if __name__ == "__main__":
    create_export_zip()
