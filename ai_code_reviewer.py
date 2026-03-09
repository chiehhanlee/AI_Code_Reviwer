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
    _classify_function_role,
    _build_verify_system_prompt, _build_verify_user_prompt,
    SCHEMA_FUNCTION, SCHEMA_FULL_FILE, SCHEMA_CROSS_FUNCTION, SCHEMA_VERIFY,
)
from llm_client import ACTIVE_BACKEND, MODEL_NAME, VERIFY_BACKEND, VERIFY_MODEL_NAME, \
    review_code, verify_findings, _parse_llm_json, is_error_response


def _run_verification_pass(report, functions):
    """Use the verifier LLM to confirm each finding and add exploit_example,
    confirmed, and severity fields in-place.
    Uses VERIFY_BACKEND/VERIFY_MODEL if set, otherwise inherits from LLM_BACKEND."""
    print(f"Running verification pass (verifier: {VERIFY_BACKEND}, "
          f"model: {VERIFY_MODEL_NAME})...", file=sys.stderr)

    system_prompt = _build_verify_system_prompt()
    total_confirmed  = 0
    total_rejected   = 0
    total_unverified = 0

    # --- Verify per-function findings ---
    for entry in report.get("functions", []):
        vulns = [v for v in entry.get("vulnerabilities", []) if isinstance(v, dict)]
        if not vulns:
            continue
        func_name = entry.get("function", "")
        source    = functions.get(func_name, {}).get("source", "")
        print(f"  Verifying: {func_name} ({len(vulns)} finding(s))", file=sys.stderr)

        user_prompt = _build_verify_user_prompt(source, vulns)
        raw = verify_findings(system_prompt, user_prompt, schema=SCHEMA_VERIFY)
        if raw is None:
            continue

        verify_map = {
            (v.get("line"), v.get("CWE_ID")): v
            for v in _parse_llm_json(raw).get("verified", [])
        }
        for vuln in vulns:
            key = (vuln.get("line"), vuln.get("CWE_ID"))
            result = verify_map.get(key)
            if result is None:
                print(f"    [WARN] verifier skipped {key[1]} at line {key[0]}", file=sys.stderr)
                vuln["confirmed"]       = None
                vuln["severity"]        = ""
                vuln["exploit_example"] = ""
                total_unverified += 1
            else:
                vuln["confirmed"]       = result.get("confirmed", True)
                vuln["severity"]        = result.get("severity", "")
                vuln["exploit_example"] = result.get("exploit_example", "")
                if vuln["confirmed"]:
                    total_confirmed += 1
                else:
                    total_rejected += 1

    # --- Verify cross-function findings ---
    cf_findings = report.get("cross_function", [])
    if cf_findings:
        # Build a combined source block from all functions involved
        involved_names = {n for v in cf_findings for n in v.get("functions_involved", [])}
        combined_source = "\n\n".join(
            f"// --- Function: {n} ---\n{functions[n]['source']}"
            for n in sorted(involved_names) if n in functions
        )
        print(f"  Verifying: cross-function findings ({len(cf_findings)} finding(s))",
              file=sys.stderr)

        user_prompt = _build_verify_user_prompt(combined_source, cf_findings)
        raw = verify_findings(system_prompt, user_prompt, schema=SCHEMA_VERIFY)
        if raw is not None:
            verify_map = {
                (v.get("line"), v.get("CWE_ID")): v
                for v in _parse_llm_json(raw).get("verified", [])
            }
            for vuln in cf_findings:
                key = (vuln.get("line"), vuln.get("CWE_ID"))
                result = verify_map.get(key)
                if result is None:
                    print(f"    [WARN] verifier skipped {key[1]} at line {key[0]}", file=sys.stderr)
                    vuln["confirmed"]       = None
                    vuln["severity"]        = ""
                    vuln["exploit_example"] = ""
                    total_unverified += 1
                else:
                    vuln["confirmed"]       = result.get("confirmed", True)
                    vuln["severity"]        = result.get("severity", "")
                    vuln["exploit_example"] = result.get("exploit_example", "")
                    if vuln["confirmed"]:
                        total_confirmed += 1
                    else:
                        total_rejected += 1

    print(f"Verification complete: {total_confirmed} confirmed, "
          f"{total_rejected} rejected, {total_unverified} unverified.", file=sys.stderr)


def _deduplicate_report(report):
    """
    Remove duplicate vulnerability findings from the report in-place.

    Deduplication keys:
    - per-function vulnerabilities:  (line, CWE_ID) within each function entry
    - cross_function findings:       (frozenset(functions_involved), CWE_ID)
    - full-file vulnerabilities:     (line, CWE_ID)
    """
    removed = 0

    # Per-function pass
    for entry in report.get("functions", []):
        vulns = entry.get("vulnerabilities", [])
        seen = set()
        deduped = []
        for v in vulns:
            key = (v.get("line"), v.get("CWE_ID"))
            if key not in seen:
                seen.add(key)
                deduped.append(v)
            else:
                removed += 1
        entry["vulnerabilities"] = deduped

    # Cross-function pass
    cf = report.get("cross_function", [])
    if cf:
        seen = set()
        deduped = []
        for v in cf:
            key = (frozenset(v.get("functions_involved", [])), v.get("CWE_ID"))
            if key not in seen:
                seen.add(key)
                deduped.append(v)
            else:
                removed += 1
        report["cross_function"] = deduped

    # Full-file fallback
    vulns = report.get("vulnerabilities", [])
    if vulns:
        seen = set()
        deduped = []
        for v in vulns:
            key = (v.get("line"), v.get("CWE_ID"))
            if key not in seen:
                seen.add(key)
                deduped.append(v)
            else:
                removed += 1
        report["vulnerabilities"] = deduped

    if removed:
        print(f"Deduplication removed {removed} duplicate finding(s).", file=sys.stderr)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AI C/C++ security reviewer")
    parser.add_argument("filepath", help="C source file to analyze")
    parser.add_argument("-I", "--include-dir", action="append", dest="include_dirs",
                        default=[], metavar="DIR",
                        help="Additional include search path (repeatable, like gcc -I)")
    parser.add_argument("-o", "--output", dest="output", default=None, metavar="FILE",
                        help="Output JSON file (default: <source>.audit.json)")
    parser.add_argument("--cluster-size", type=int, default=8, metavar="N",
                        help="Max functions per cross-function cluster (default: 8)")
    parser.add_argument("--timeout", type=int, default=None, metavar="N",
                        help="API timeout in seconds (default: API_TIMEOUT_SECS env or 300)")
    args = parser.parse_args()

    import llm_client
    filepath = args.filepath
    output_path = args.output or (os.path.splitext(filepath)[0] + ".audit.json")
    include_dirs = INCLUDE_DIRS + [os.path.abspath(d) for d in args.include_dirs]
    if args.timeout is not None:
        llm_client.API_TIMEOUT = args.timeout

    if include_dirs:
        print(f"Include search paths: {include_dirs}", file=sys.stderr)
    print(f"Analyzing {filepath}...", file=sys.stderr)

    code_content = read_code_file(filepath, include_dirs=include_dirs)
    report = {"file": filepath, "model": MODEL_NAME}
    functions = {}   # populated during AST path; used by verification pass

    if HAS_PYCPARSER:
        print("Extracting AST and function dependencies...", file=sys.stderr)
        functions = analyze_ast(code_content, filepath)  # noqa: F841 (used by verify pass)

        if not functions:
            print("Failed to build AST. Falling back to full file review...", file=sys.stderr)
            pruned_content = prune_context(code_content)
            report["mode"] = "full-file"
            system_prompt = _build_system_prompt()
            user_prompt = _build_user_prompt(pruned_content)
            raw = review_code(system_prompt, user_prompt, schema=SCHEMA_FULL_FILE)
            if is_error_response(raw):
                print(f"[ERROR] Full-file analysis failed: {raw}", file=sys.stderr)
                report["error"] = raw
            else:
                report.update(_parse_llm_json(raw))
        else:
            target_relpath = os.path.relpath(os.path.abspath(filepath))
            target_funcs = {n: d for n, d in functions.items()
                            if d['file'] == target_relpath}
            total = len(target_funcs)
            print(f"Found {len(functions)} functions ({total} in target file). "
                  f"Auditing function-by-function... "
                  f"(backend: {ACTIVE_BACKEND}, model: {MODEL_NAME})", file=sys.stderr)
            report["mode"] = "function-by-function"
            report["functions"] = []

            # Build header context once — shared across all function reviews
            file_map = _build_file_map(code_content)
            file_sections = _extract_file_sections(code_content, file_map)
            header_context = ""
            for fname, content in file_sections.items():
                if fname.endswith('.h') and fname != target_relpath:
                    header_context += f"// --- Header: {fname} ---\n{content}\n"

            for idx, (func_name, data) in enumerate(target_funcs.items(), start=1):
                pct = int(idx / total * 100)
                print(f"[{idx}/{total}] ({pct}%) Auditing: {func_name}", file=sys.stderr)

                context_code = header_context

                system_prompt = _build_system_prompt(func_name=func_name)
                user_prompt = _build_user_prompt(data['source'], func_name=func_name,
                                                 context_code=context_code)
                raw = review_code(system_prompt, user_prompt, func_name=func_name, schema=SCHEMA_FUNCTION)
                if is_error_response(raw):
                    print(f"[ERROR] {func_name}: {raw}", file=sys.stderr)
                    report["functions"].append(
                        {"function": func_name, "vulnerabilities": [], "error": raw})
                    continue
                entry = _parse_llm_json(raw)
                report["functions"].append(entry)

            # --- Cross-function pass ---
            print(f"Running cross-function analysis pass... "
                  f"(backend: {ACTIVE_BACKEND}, model: {MODEL_NAME})", file=sys.stderr)
            clusters = build_call_clusters(functions, target_funcs,
                                           max_cluster_size=args.cluster_size)
            if clusters:
                cross_function_results = []
                system_prompt_cf = _build_cross_function_system_prompt()
                for cluster_idx, cluster in enumerate(clusters, start=1):
                    cluster_names = sorted(cluster)
                    cluster_sources = {n: functions[n]['source'] for n in cluster_names}

                    # Skip clusters with no unbalanced memory operations — every
                    # cross-function CWE (401/415/416/476) requires at least one
                    # function that allocates-without-freeing (escaping pointer) or
                    # frees-without-allocating (external freer). A cluster whose only
                    # memory-active function both allocates AND frees internally has
                    # no cross-boundary concern and would cause LLM hallucinations.
                    roles = [_classify_function_role(src) for src in cluster_sources.values()]
                    has_unbalanced = any(
                        r in ("ALLOCATES memory (returns pointer to caller)",
                              "FREES memory (calls free() on its argument)")
                        for r in roles
                    )
                    if not has_unbalanced:
                        print(
                            f"  [cluster {cluster_idx}/{len(clusters)}] "
                            f"Skipping {', '.join(cluster_names)} — no unbalanced alloc/free",
                            file=sys.stderr,
                        )
                        continue

                    print(
                        f"  [cluster {cluster_idx}/{len(clusters)}] "
                        f"Analyzing: {', '.join(cluster_names)}",
                        file=sys.stderr,
                    )
                    user_prompt_cf = _build_cross_function_user_prompt(cluster_sources)
                    raw_cf = review_code(
                        system_prompt_cf, user_prompt_cf,
                        func_name=f"__cross_function_cluster_{cluster_idx}",
                        schema=SCHEMA_CROSS_FUNCTION,
                    )
                    if is_error_response(raw_cf):
                        print(f"[ERROR] cluster {cluster_idx}: {raw_cf}", file=sys.stderr)
                        continue
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
        raw = review_code(system_prompt, user_prompt, schema=SCHEMA_FULL_FILE)
        if is_error_response(raw):
            print(f"[ERROR] Full-file analysis failed: {raw}", file=sys.stderr)
            report["error"] = raw
        else:
            report.update(_parse_llm_json(raw))

    _deduplicate_report(report)
    _run_verification_pass(report, functions)

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Audit report written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
