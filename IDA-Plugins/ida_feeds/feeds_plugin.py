import os

import ida_auto
import ida_idaapi
import ida_kernwin
import ida_loader


class Plugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = 'Hex-Rays IDA Feeds Plugin'
    help = 'Massively Analyze Signatures'
    wanted_name = 'IDA Feeds'
    wanted_hotkey = 'Ctrl-Shift-F5'

    def __init__(self):
        super().__init__()
        self.arg = None
        self.form = None
        self.hooks = None
        self.popup_hooks = None
        self.mgr = None
        # Define the custom action
        self.action_name = 'my:ida_feeds_popup_action'
        self.action_desc = ida_kernwin.action_desc_t(
            self.action_name,  # The internal action name
            'Open IDA Feeds',  # Label shown in the context menu
            PopupActionHandler(self),  # The action handler
            None,  # Shortcut (None if no shortcut)
            'IDA Feeds Plugin',  # Tooltip
            -1,  # Icon ID (-1 means no icon)
        )

    def init(self):
        env_interactive = os.environ.get('IDA_IS_INTERACTIVE')
        if not env_interactive or env_interactive == '0':
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.register_action(self.action_desc)
        if self.popup_hooks is None:
            self.popup_hooks = ActionPopupHooks()
            self.popup_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        dependencies_loaded = True
        failed_dependency = []
        try:
            from feeds import env
            from feeds.ui.controller import Manager
        except ImportError as e:
            dependencies_loaded = False
            failed_dependency.append(e.name)

        if not dependencies_loaded:
            ida_kernwin.warning(
                f'IDA Feeds plugin cannot run due to missing dependencies: {failed_dependency}.'
            )
            return

        if not ida_auto.auto_is_ok():
            ida_kernwin.warning(
                'IDA Feeds plugin cannot be launched until auto-analysis is complete. Please wait.'
            )
            return

        if not ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
            ida_kernwin.warning(
                'IDA Feeds plugin requires a binary to be loaded before launching. Please open a binary first.'
            )
            return

        # Hook for handling the UI populating_widget_popup and undo/redo
        try:
            if self.mgr is None:
                self.mgr = Manager(env.IDB_PATH)
            if self.form is None:
                self.form = PluginView(mgr=self.mgr)
            if self.hooks is None:
                self.hooks = PluginHooks(mgr=self.mgr, plugin_instance=self)
                self.hooks.hook()
            self.form.Show('IDA Feeds')
        except Exception as e:
            ida_kernwin.msg(f'IDA Feeds plugin, exception {e} trying to run plugin.')

    def term(self):
        try:
            ida_kernwin.unregister_action(self.action_name)
            if self.popup_hooks is not None:
                self.popup_hooks.unhook()
                self.popup_hooks = None
            if self.hooks is not None:
                self.hooks.unhook()
                self.hooks = None
        except Exception as e:
            ida_kernwin.msg(f'IDA Feeds plugin, exception {e} trying to unhook hooks.')

        self.hooks = None
        self.mgr = None
        self.form = None

    def test(self):
        pass


def PLUGIN_ENTRY():
    return Plugin()


class PopupActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin_instance):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin_instance = plugin_instance

    def activate(self, ctx):
        self.plugin_instance.run(self.plugin_instance.arg)
        return 1

    def update(self, ctx):
        # Enable this action only if the context allows (always enabled for now)
        return ida_kernwin.AST_ENABLE_ALWAYS


class ActionPopupHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def populating_widget_popup(self, widget, popup, ctx):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_SIGNS:
            # Attach the custom action to the context menu
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                'my:ida_feeds_popup_action',
                None,
                ida_kernwin.SETMENU_FIRST | ida_kernwin.SETMENU_ENSURE_SEP,
            )
        return super().populating_widget_popup(widget, popup, ctx)

    def hook(self):
        return ida_kernwin.UI_Hooks.hook(self)

    def unhook(self):
        return ida_kernwin.UI_Hooks.unhook(self)


class PluginHooks(ida_kernwin.UI_Hooks):
    REFRESH_TIME = 500

    def __init__(self, mgr, plugin_instance):
        ida_kernwin.UI_Hooks.__init__(self)
        self.idle_callback = None
        self.mgr = mgr
        self.plugin_instance = plugin_instance

    def on_refresh_timer(self):
        # ida_kernwin.is_refresh_requested(ida_kernwin.IWID_SIGNS) cannot be used,
        # refresh flags may be reset by ida before running the callback;
        if self.mgr is not None:
            self.mgr.refresh_content()
        return self.REFRESH_TIME

    def widget_visible(self, widget):
        if widget == self.plugin_instance.form.parent:
            if self.idle_callback is None:
                self.idle_callback = ida_kernwin.register_timer(
                    self.REFRESH_TIME, self.on_refresh_timer
                )

    def widget_closing(self, widget):
        if widget == self.plugin_instance.form.parent:
            if self.idle_callback is not None:
                ida_kernwin.unregister_timer(self.idle_callback)
                self.idle_callback = None

    def hook(self):
        return ida_kernwin.UI_Hooks.hook(self)

    def unhook(self):
        return ida_kernwin.UI_Hooks.unhook(self)


class PluginView(ida_kernwin.PluginForm):
    WINDOW_TITLE = 'IDA Feeds'

    def __init__(self, mgr):
        super(PluginView, self).__init__()
        self.parent = None
        self.mgr = mgr

    def OnCreate(self, form):
        from PySide6.QtWidgets import QVBoxLayout

        from feeds.ui.view import FeedsView

        self.parent = form
        if self.mgr is not None:
            self.mgr.set_view(FeedsView())

            layout = QVBoxLayout()
            layout.addWidget(self.mgr.view)

            _form = self.FormToPyQtWidget(form)
            _form.setLayout(layout)

            self.mgr.populate_model()
            self.mgr.refresh_content(force_refresh=True)

    def OnClose(self, form):
        self.mgr.set_view(None)

    def Show(self, caption):
        ida_kernwin.PluginForm.Show(
            self, self.WINDOW_TITLE, options=ida_kernwin.PluginForm.WOPN_TAB
        )
