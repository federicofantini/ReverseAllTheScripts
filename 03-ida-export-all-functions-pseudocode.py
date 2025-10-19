from idautils import Functions
from ida_funcs import get_func, get_func_name
from ida_bytes import get_full_flags
from ida_kernwin import msg
import os
import re

try:
    from ida_hexrays import decompile
except ImportError:
    print("Hex-Rays decompiler not available. This script needs Hex-Rays.")
    raise SystemExit(1)

out_dir = os.path.join(os.getcwd(), "ida_pseudocode_exports")
os.makedirs(out_dir, exist_ok=True)

count = 0
for ea in Functions():
    f = get_func(ea)
    if not f:
        continue
    name = get_func_name(ea)
    # skip thunks / import stubs if you want; simple filter:
    if f.flags & FUNC_THUNK:
        continue

    try:
        cfunc = decompile(f)            # returns a cfunc_t object
        text = str(cfunc)               # pseudocode as text
    except Exception as e:
        print("Decompile failed for %s @ 0x%X: %s" % (name, ea, e))
        continue

    # Sanitize the function name to make it a valid filename
    safe_name = "%s_0x%X.c" % (name, ea)
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', safe_name)  # Replace invalid characters with underscores
    
    out_path = os.path.join(out_dir, safe_name)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("// Function: %s @ 0x%X\n\n" % (name, ea))
        fh.write(text)
    count += 1
    print("Exported %s" % out_path)

print("Done. Exported %d functions into %s" % (count, out_dir))
