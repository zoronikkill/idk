"""
summary: retrieve & dump current selection

description:
  Shows how to retrieve the selection from a listing
  widget ("IDA View-A", "Hex View-1", "Pseudocode-A", ...) as
  two "cursors", and from there retrieve (in fact, generate)
  the corresponding text.

  After running this script:

    * select some text in one of the listing widgets (i.e.,
      "IDA View-*", "Local Types", "Pseudocode-*")
    * press Ctrl+Shift+S to dump the selection

level: advanced
"""

import ida_kernwin
import ida_lines

def get_widget_lines(widget, tp0, tp1):
    """
    get lines between places tp0 and tp1 in widget
    """
    ud = ida_kernwin.get_viewer_user_data(widget)
    lnar = ida_kernwin.linearray_t(ud)
    lnar.set_place(tp0.at)
    lines = []
    while True:
        cur_place = lnar.get_place()
        first_line_ref = ida_kernwin.l_compare2(cur_place, tp0.at, ud)
        last_line_ref = ida_kernwin.l_compare2(cur_place, tp1.at, ud)
        if last_line_ref > 0: # beyond last line
            break
        line = ida_lines.tag_remove(lnar.down())
        if last_line_ref == 0: # at last line
            line = line[0:tp1.x]
        elif first_line_ref == 0: # at first line
            line = " " * tp0.x + line[tp0.x:]
        lines.append(line)
    return lines

class dump_selection_handler_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if ctx.has_flag(ida_kernwin.ACF_HAS_SELECTION):
            lines = get_widget_lines(ctx.widget, ctx.cur_sel._from, ctx.cur_sel.to)
            for line in lines:
                print(line)
        return 1

    def update(self, ctx):
        ok_widgets = [
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_TILVIEW,
            ida_kernwin.BWN_PSEUDOCODE,
        ]
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type in ok_widgets \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


# -----------------------------------------------------------------------
# create actions (and attach them to IDA View-A's context menu if possible)
ACTION_NAME = "dump_selection"
ACTION_SHORTCUT = "Ctrl+Shift+S"

if ida_kernwin.unregister_action(ACTION_NAME):
    print("Unregistered previously-registered action \"%s\"" % ACTION_NAME)

if ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Dump selection",
            dump_selection_handler_t(),
            ACTION_SHORTCUT)):
    print("Registered action \"%s\"" % ACTION_NAME)

# dump current selection
p0 = ida_kernwin.twinpos_t()
p1 = ida_kernwin.twinpos_t()
view = ida_kernwin.get_last_widget(ida_kernwin.IWID_ANY_LISTING)
if ida_kernwin.read_selection(view, p0, p1):
    lines = get_widget_lines(view, p0, p1)
    print("\n".join(lines))

