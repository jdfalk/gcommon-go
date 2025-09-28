#!/usr/bin/env python3
# file: scripts/deprecate_v1_modules.py
# version: 1.0.0
# guid: deprecate-v1-modules-script

"""
Script to automatically add deprecation notices to all v1 protobuf modules.

This script:
1. Scans all pkg/*pb directories for go.mod files
2. Adds deprecation comments to v1 go.mod files
3. Optionally creates doc.go files with deprecation notices
4. Updates version numbers in file headers
"""

import sys
import re
from pathlib import Path
from typing import List, Tuple
import argparse
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def find_pkg_modules(pkg_dir: Path) -> List[Path]:
    """Find all *pb directories in pkg/ that contain go.mod files."""
    modules = []
    if not pkg_dir.exists():
        logger.error(f"Package directory not found: {pkg_dir}")
        return modules
    
    for item in pkg_dir.iterdir():
        if item.is_dir() and item.name.endswith('pb'):
            go_mod_path = item / 'go.mod'
            if go_mod_path.exists():
                modules.append(item)
                logger.info(f"Found module: {item}")
    
    return modules

def has_v2_module(module_path: Path) -> bool:
    """Check if a v2 subdirectory exists for this module."""
    v2_path = module_path / 'v2'
    v2_go_mod = v2_path / 'go.mod'
    return v2_go_mod.exists()

def read_go_mod(go_mod_path: Path) -> Tuple[str, bool]:
    """Read go.mod file and check if it's already deprecated."""
    content = go_mod_path.read_text()
    is_deprecated = 'Deprecated:' in content
    return content, is_deprecated

def add_deprecation_to_go_mod(go_mod_path: Path, module_name: str, has_v2: bool) -> bool:
    """Add deprecation comment to go.mod file."""
    content, is_deprecated = read_go_mod(go_mod_path)
    
    if is_deprecated:
        logger.info(f"Module {module_name} is already deprecated")
        return False
    
    lines = content.split('\n')
    
    # Find the module line
    module_line_idx = -1
    for i, line in enumerate(lines):
        if line.strip().startswith('module '):
            module_line_idx = i
            break
    
    if module_line_idx == -1:
        logger.error(f"Could not find module line in {go_mod_path}")
        return False
    
    # Update version in header if present
    for i, line in enumerate(lines[:10]):  # Check first 10 lines for header
        if line.strip().startswith('// version:'):
            # Increment patch version
            version_match = re.search(r'(\d+)\.(\d+)\.(\d+)', line)
            if version_match:
                major, minor, patch = version_match.groups()
                new_patch = int(patch) + 1
                new_version = f"{major}.{minor}.{new_patch}"
                lines[i] = re.sub(r'\d+\.\d+\.\d+', new_version, line)
                logger.info(f"Updated version to {new_version}")
            break
    
    # Add deprecation comment before module line
    if has_v2:
        deprecation_lines = [
            "",
            f"// Deprecated: This module is deprecated. Use {module_name}/v2 instead.",
            "// The v2 module provides enhanced functionality, additional methods, and improved protobuf definitions."
        ]
    else:
        deprecation_lines = [
            "",
            "// Deprecated: This module is deprecated and will be removed in a future version.",
            "// Please migrate to alternative authentication mechanisms."
        ]
    
    # Insert deprecation lines before module declaration
    for i, dep_line in enumerate(reversed(deprecation_lines)):
        lines.insert(module_line_idx, dep_line)
    
    # Write back to file
    go_mod_path.write_text('\n'.join(lines))
    logger.info(f"Added deprecation notice to {go_mod_path}")
    return True

def create_deprecation_doc_go(module_path: Path, module_name: str, has_v2: bool) -> bool:
    """Create doc.go file with deprecation notice."""
    doc_go_path = module_path / 'doc.go'
    
    if doc_go_path.exists():
        logger.info(f"doc.go already exists for {module_name}")
        return False
    
    package_name = module_path.name  # e.g., 'authpb', 'commonpb'
    
    if has_v2:
        migration_info = f"""
//
// Migration Guide:
//   Replace: {module_name}
//   With:    {module_name}/v2
//
// The v2 API provides enhanced functionality while maintaining compatibility
// with core v1 operations. See the v2 documentation for migration details."""
    else:
        migration_info = """
//
// This package will be removed in a future version.
// Please plan migration to alternative solutions."""
    
    content = f"""// file: {module_path.relative_to(module_path.parent.parent)}/doc.go
// version: 1.0.0
// guid: doc-{package_name}-v1-deprecation

// Package {package_name} provides v1 protocol buffer definitions.
//
// Deprecated: This package is deprecated.{migration_info}
package {package_name}
"""
    
    doc_go_path.write_text(content)
    logger.info(f"Created doc.go for {module_name}")
    return True

def deprecate_module(module_path: Path, create_doc_files: bool = True) -> bool:
    """Deprecate a single module."""
    go_mod_path = module_path / 'go.mod'
    if not go_mod_path.exists():
        logger.error(f"No go.mod found in {module_path}")
        return False
    
    # Extract module name from go.mod
    content = go_mod_path.read_text()
    module_match = re.search(r'module\s+([\w./\-]+)', content)
    if not module_match:
        logger.error(f"Could not extract module name from {go_mod_path}")
        return False
    
    module_name = module_match.group(1)
    has_v2 = has_v2_module(module_path)
    
    logger.info(f"Processing module: {module_name} (has_v2: {has_v2})")
    
    # Add deprecation to go.mod
    go_mod_updated = add_deprecation_to_go_mod(go_mod_path, module_name, has_v2)
    
    # Create doc.go if requested
    doc_created = False
    if create_doc_files:
        doc_created = create_deprecation_doc_go(module_path, module_name, has_v2)
    
    return go_mod_updated or doc_created

def main():
    parser = argparse.ArgumentParser(description='Deprecate v1 protobuf modules')
    parser.add_argument('--pkg-dir', type=Path, default=Path.cwd() / 'pkg',
                      help='Path to pkg directory (default: ./pkg)')
    parser.add_argument('--no-doc', action='store_true',
                      help='Skip creating doc.go files')
    parser.add_argument('--module', type=str,
                      help='Deprecate specific module only (e.g., authpb)')
    parser.add_argument('--dry-run', action='store_true',
                      help='Show what would be done without making changes')
    
    args = parser.parse_args()
    
    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
    
    pkg_dir = args.pkg_dir.resolve()
    if not pkg_dir.exists():
        logger.error(f"Package directory not found: {pkg_dir}")
        return 1
    
    # Find modules to process
    if args.module:
        module_path = pkg_dir / args.module
        if not module_path.exists() or not (module_path / 'go.mod').exists():
            logger.error(f"Module not found: {module_path}")
            return 1
        modules = [module_path]
    else:
        modules = find_pkg_modules(pkg_dir)
    
    if not modules:
        logger.error("No modules found to deprecate")
        return 1
    
    logger.info(f"Found {len(modules)} modules to process")
    
    success_count = 0
    for module_path in modules:
        logger.info(f"\n--- Processing {module_path.name} ---")
        
        if args.dry_run:
            logger.info(f"Would deprecate: {module_path}")
            logger.info(f"  - Has v2: {has_v2_module(module_path)}")
            logger.info(f"  - Would create doc.go: {not args.no_doc}")
            success_count += 1
        else:
            if deprecate_module(module_path, not args.no_doc):
                success_count += 1
                logger.info(f"✓ Successfully processed {module_path.name}")
            else:
                logger.info(f"• No changes needed for {module_path.name}")
    
    logger.info(f"\nCompleted: {success_count}/{len(modules)} modules processed")
    return 0

if __name__ == '__main__':
    sys.exit(main())