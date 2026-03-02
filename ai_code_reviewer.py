#!/usr/bin/env python3
import sys
import os
import json

from context_builder import (
    INCLUDE_DIRS, HAS_PYCPARSER,
    read_code_file, prune_context, analyze_ast,
    _build_file_map, _extract_file_sections,
    _build_system_prompt, _build_user_prompt,
    build_call_clusters,
    _build_cross_function_system_prompt,
    _build_cross_function_user_prompt,
)
from llm_client import MODEL_NAME, review_code, _parse_llm_json


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AI C/C++ security reviewer")
    parser.add_argument("filepath", help="C source file to analyze")
    parser.add_argument("-I", "--include-dir", action="append", dest="include_dirs",
                        default=[], metavar="DIR",
                        help="Additional include search path (repeatable, like gcc -I)")
    parser.add_argument("-o", "--output", dest="output", default=None, metavar="FILE",
                        help="Output JSON file (default: <source>.audit.json)")
    args = parser.parse_args()

    filepath = args.filepath
    output_path = args.output or (os.path.splitext(filepath)[0] + ".audit.json")
    include_dirs = INCLUDE_DIRS + [os.path.abspath(d) for d in args.include_dirs]

    if include_dirs:
        print(f"Include search paths: {include_dirs}", file=sys.stderr)
    print(f"Analyzing {filepath}...", file=sys.stderr)

    code_content = read_code_file(filepath, include_dirs=include_dirs)
    report = {"file": filepath, "model": MODEL_NAME}

    if HAS_PYCPARSER:
        print("Extracting AST and function dependencies...", file=sys.stderr)
        functions = analyze_ast(code_content, filepath)

        if not functions:
            print("Failed to build AST. Falling back to full file review...", file=sys.stderr)
            pruned_content = prune_context(code_content)
            report["mode"] = "full-file"
            system_prompt = _build_system_prompt()
            user_prompt = _build_user_prompt(pruned_content)
            report.update(_parse_llm_json(review_code(system_prompt, user_prompt)))
        else:
            target_basename = os.path.basename(filepath)
            target_funcs = {n: d for n, d in functions.items()
                            if d['file'] == target_basename}
            total = len(target_funcs)
            print(f"Found {len(functions)} functions ({total} in target file). "
                  f"Auditing function-by-function...", file=sys.stderr)
            report["mode"] = "function-by-function"
            report["functions"] = []

            # Build header context once — shared across all function reviews
            file_map = _build_file_map(code_content)
            file_sections = _extract_file_sections(code_content, file_map)
            header_context = ""
            for fname, content in file_sections.items():
                if fname.endswith('.h') and fname != target_basename:
                    header_context += f"// --- Header: {fname} ---\n{content}\n"

            for idx, (func_name, data) in enumerate(target_funcs.items(), start=1):
                pct = int(idx / total * 100)
                print(f"[{idx}/{total}] ({pct}%) Auditing: {func_name}", file=sys.stderr)

                context_code = header_context
                dependencies = [c for c in data['calls'] if c in functions and c != func_name]
                if dependencies:
                    for dep in dependencies:
                        context_code += f"// --- Context Function: {dep} ---\n"
                        context_code += functions[dep]['source'] + "\n"

                system_prompt = _build_system_prompt(func_name=func_name)
                user_prompt = _build_user_prompt(data['source'], func_name=func_name,
                                                 context_code=context_code)
                raw = review_code(system_prompt, user_prompt, func_name=func_name)
                entry = _parse_llm_json(raw)
                report["functions"].append(entry)

            # --- Cross-function pass ---
            print("Running cross-function analysis pass...", file=sys.stderr)
            clusters = build_call_clusters(functions, target_funcs)
            if clusters:
                cross_function_results = []
                system_prompt_cf = _build_cross_function_system_prompt()
                for cluster_idx, cluster in enumerate(clusters, start=1):
                    cluster_names = sorted(cluster)
                    print(
                        f"  [cluster {cluster_idx}/{len(clusters)}] "
                        f"Analyzing: {', '.join(cluster_names)}",
                        file=sys.stderr,
                    )
                    cluster_sources = {n: functions[n]['source'] for n in cluster_names}
                    user_prompt_cf = _build_cross_function_user_prompt(cluster_sources)
                    raw_cf = review_code(
                        system_prompt_cf, user_prompt_cf,
                        func_name=f"__cross_function_cluster_{cluster_idx}",
                    )
                    parsed_cf = _parse_llm_json(raw_cf)
                    findings = parsed_cf.get("cross_function_vulnerabilities", [])
                    if findings:
                        cross_function_results.extend(findings)
                if cross_function_results:
                    report["cross_function"] = cross_function_results
    else:
        print("Pruning code context...", file=sys.stderr)
        pruned_content = prune_context(code_content)
        report["mode"] = "full-file"
        system_prompt = _build_system_prompt()
        user_prompt = _build_user_prompt(pruned_content)
        report.update(_parse_llm_json(review_code(system_prompt, user_prompt)))

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Audit report written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
