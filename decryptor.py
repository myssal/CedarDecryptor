import os
import re
import shutil

class Decryptor:
    def __init__(self, input_folder: str):
        """
        Initialize the Decryptor with input folder.
        Output folder will be created under input folder by default.
        """
        self.input_folder = input_folder
        self.output_folder = os.path.join(input_folder, "DecryptedBundles")
        os.makedirs(self.output_folder, exist_ok=True)

    def build_manifest_map(self, manifest_file: str, package_name: str) -> dict:
        """
        Reads a .bytes manifest file and returns a dict mapping: full_filename -> hash
        """
        print(f"Build manifest map from {manifest_file}")

        package_name_lower = package_name.lower()
        if "defaultpackage" in package_name_lower:
            extension = b"bundle"
        elif "rawpackage" in package_name_lower:
            extension = b"rawfile"
        else:
            extension = b"bundle"

        with open(manifest_file, "rb") as f:
            data = f.read()

        package_name_bytes = package_name_lower.encode('utf-8')

        # package_name + any bytes + extension + optional 6 bytes + 32-character hash
        regex_pattern = re.compile(package_name_bytes + b"(.*?)" + extension + b".{6}([0-9a-f]{32})", re.DOTALL)

        matches = regex_pattern.findall(data)

        mapping = {}
        for name_bytes, hash_bytes in matches:
            full_name_bytes = package_name_bytes + name_bytes + extension
            full_name = full_name_bytes.decode('utf-8', errors='ignore')
            hash_str = hash_bytes.decode('ascii')
            mapping[full_name] = hash_str

        return mapping

    def gather_manifest_maps(self, package_folder: str, package_name: str) -> dict:
        """
        Scan all ManifestFiles/*.bytes in a package folder and combine all filename->hash mappings.
        """
        manifest_folder = os.path.join(package_folder, "ManifestFiles")
        combined_map = {}

        for root, _, files in os.walk(manifest_folder):
            for file in files:
                if file.endswith(".bytes"):
                    path = os.path.join(root, file)
                    print(f"Parse manifest from {path}")
                    combined_map.update(self.build_manifest_map(path, package_name))
                    print(f"Current combined map length: {len(combined_map)}")

        return combined_map

    def find_cache_files(self, package_folder: str) -> list:
        """
        Scan CacheFiles folder and return a list of all files (including in subfolders).
        """
        cache_folder = os.path.join(package_folder, "CacheFiles")
        cache_files = []

        for root, _, files in os.walk(cache_folder):
            for file in files:
                if "__data" in file:
                    cache_files.append(os.path.join(root, file))

        return cache_files

    def decrypt_file(self, input_path: str, output_path: str):
        """
        Just copy files for now
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        shutil.copy2(input_path, output_path)

    def process_package(self, package_folder: str, package_name: str):
        """
        Process a single package: parse manifests, match cached files, and decrypt.
        """
        print(f"Processing package: {package_folder}")

        manifest_map = self.gather_manifest_maps(package_folder, package_name)
        print(f"Found {len(manifest_map)} files in manifest.")

        cache_files = self.find_cache_files(package_folder)
        print(f"Found {len(cache_files)} cached files.")

        restored_count = 0
        for cache_file in cache_files:
            hash_name = os.path.basename(os.path.dirname(cache_file))

            for original_name, hash_value in manifest_map.items():
                if hash_name.lower().startswith(hash_value.lower()):
                    output_path = os.path.join(self.output_folder, package_name, original_name)
                    self.decrypt_file(cache_file, output_path)
                    restored_count += 1
                    break

        print(f"Restored and decrypted {restored_count} files from {package_folder}.")

    def process_packages(self):
        """
        Process DefaultPackage and RawPackage folders
        """
        if not os.path.exists(self.input_folder):
            print(f"Input folder does not exist: {self.input_folder}")
            return

        for package_name in ["DefaultPackage", "RawPackage"]:
            package_folder = os.path.join(self.input_folder, package_name)
            if os.path.exists(package_folder):
                self.process_package(package_folder, package_name)
            else:
                print(f"Package folder not found: {package_folder}")

        print(f"All done! Decrypted files are in {self.output_folder}")

