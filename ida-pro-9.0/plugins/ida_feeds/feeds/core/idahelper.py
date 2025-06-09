import os
from pathlib import Path
import ida_funcs
import ida_libfuncs
import ida_idp
import ida_auto
import ida_undo
import ida_loader
import ida_diskio
import ida_idaapi
import ida_name
import ida_segment
import ida_bytes
import idc


class SigHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.matched_funcs = dict()

    def idasgn_matched_ea(self, ea, name, lib_name):
        self.matched_funcs[ea] = name

class IDA:
    def __init__(self):
        self.path = True

    @staticmethod
    def _is_rust_binary():
        return ida_loader.find_plugin("")

    @staticmethod
    def is_rust_binary():
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "rust_begin_unwind")
        if ea != ida_idaapi.BADADDR:
            return True

        ea1 = 0
        ea2 = ida_idaapi.BADADDR
        segment = ida_segment.get_segm_by_name(".rodata")
        if segment is not None:
            ea1 = segment.start_ea
            ea2 = segment.end_ea

        ea = ida_bytes.find_bytes('rustc-'.encode(), ea1, ea2)

        return ea != ida_idaapi.BADADDR

    @staticmethod
    def get_ida_sig_dir():
        return ida_diskio.idadir(ida_diskio.SIG_SUBDIR)

    @staticmethod
    def get_ida_bin_dir():
        return idc.idadir()

    @staticmethod
    def get_ida_flair_dir():
        return idc.idadir()

    @staticmethod
    def save_idb_copy(new_filename: str):
        try:
            if ida_loader.save_database(new_filename, 0):
                print(f"Database successfully saved to {new_filename}")
            else:
                print(f"Failed to save the database to {new_filename}")
        except Exception as e:
            print(f"An error occurred while saving the database: {e}")

    @staticmethod
    def get_applied_sigs_dict(intersect_with: {} = None):
        applied_sigs = {}
        for i in range(ida_funcs.get_idasgn_qty()):
            if ida_funcs.calc_idasgn_state(i) == ida_funcs.IDASGN_APPLIED:
                signame, _, nmatches = ida_funcs.get_idasgn_desc_with_matches(i)
                try:
                    path = ida_libfuncs.get_idasgn_path_by_short_name(signame)
                    if path is not None:
                        signame = os.path.realpath(path)
                except:
                    pass

                applied_sigs[signame] = {"matches": nmatches}

        if intersect_with is not None:
            return  {key: applied_sigs[key] for key in (applied_sigs.keys() & intersect_with.keys())}

        return applied_sigs

    @staticmethod
    def get_applied_sigs():
        applied_sigs = []
        for i in range(ida_funcs.get_idasgn_qty()):
            if ida_funcs.calc_idasgn_state(i) == ida_funcs.IDASGN_APPLIED:
                signame, optlibs, nmatches = ida_funcs.get_idasgn_desc_with_matches(i)
                applied_sigs.append((signame, optlibs, nmatches))

        return applied_sigs

    @staticmethod
    def get_sig_name(file):
        try:
            return ida_funcs.get_idasgn_title(file)
        except Exception as e:
            print(f'{file}: {e}')
            return ''

    @staticmethod
    def create_undo(label: str="Initial state, auto analysis"):
        if ida_undo.create_undo_point("ida_feeds:", label):
            print(f"Successfully created an undo point...")
        else:
            print(f"Failed to created an undo point...")

    @staticmethod
    def perform_undo():
        if ida_undo.perform_undo():
            print(f"Successfully reverted database changes...")
        else:
            print(f"Failed to revert database changes...")

    @staticmethod
    def apply_sig_list(sig_list):
        for sig in sig_list:
            IDA.create_undo('Apply signature ' + Path(sig['path']).name)
            if not ida_funcs.plan_to_apply_idasgn(sig['path']):
                print(f"plan_to_apply_idasgn() failed for {sig['path']}")

                if not ida_auto.auto_wait():
                    break

    @staticmethod
    def get_sig_waiting_queue():
        items = 0
        for item in range(ida_funcs.get_idasgn_qty()):
            state = ida_funcs.calc_idasgn_state(item)
            # Count sig waiting (planned or currently applying)
            if state == ida_funcs.IDASGN_PLANNED or state == ida_funcs.IDASGN_CURRENT:
                items = items + 1
        return items

    @staticmethod
    def get_sig_index(sig_file_name: str):
        for index in range(0, ida_funcs.get_idasgn_qty()):
            fname, _, _ = ida_funcs.get_idasgn_desc_with_matches(index)
            if fname == sig_file_name:
                return index
        return -1

    @staticmethod
    def apply_sig_file(sig_file_name: str):
        if not os.path.isfile(sig_file_name):
            print(f"The specified value {sig_file_name} is not a valid file name")
            return

        root, extension = os.path.splitext(sig_file_name)
        if extension != ".sig":
            print(f"The specified value {sig_file_name} is not a valid sig file")
            return

        # Install hook on IDB to collect func_matches
        sig_hook = SigHooks()
        sig_hook.hook()

        # Start apply process and wait for it
        ida_funcs.plan_to_apply_idasgn(sig_file_name)
        idx = IDA.get_sig_index(sig_file_name)
        if idx < 0:
            return None

        iterations = 0
        while True:
            iterations += 1
            state = ida_funcs.calc_idasgn_state(idx)
            if state == ida_funcs.IDASGN_BADARG:
                break
            if state == ida_funcs.IDASGN_APPLIED:
                break
            if not ida_auto.auto_wait():
                break
            if iterations > 128:
                break

        matches = {
            "signature": sig_file_name,
            "matches": len(sig_hook.matched_funcs),
            "matched_functions": []
        }

        for fea in sig_hook.matched_funcs:
            func_details = f'<0x{fea:x}> {sig_hook.matched_funcs[fea]}'
            matches['matched_functions'].append(func_details)
            matches['matched_functions'] = sorted(matches['matched_functions'])

        sig_hook.unhook()

        return matches
