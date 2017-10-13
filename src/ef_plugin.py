import logging
import pkgutil
import inspect
import importlib
import os, sys

logger = logging.getLogger(__name__)

def ef_plugin(service_name):
  """
  Decorator for ef plugin classes. Any wrapped classes should contain a run() method which executes the plugin code.

  Args:
    service_name (str): The name of the service being extended.

  Example:
    @ef_plugin('ef-generate')
    class NewRelicPlugin(object):

      def run(self):
        exec_code()
  """
  def class_rebuilder(cls):
    class EFPlugin(cls):
      """Base class of all ef plugins. Defines which service is extended and provides the EFContext object to the plugin"""
      def __init__(self, context):
        self.service = service_name
        self.context = context

      def __getattribute__(self, attr_name):
        obj = super(EFPlugin, self).__getattribute__(attr_name)
        return obj
    return EFPlugin
  return class_rebuilder


def run_plugins(context_obj):
  """
  Execs all loaded plugins designated for the service calling the function.

  Args:
    context_obj (obj:EFContext): The EFContext object created by the service.
  """
  plugins_loaded = False
  service_name = os.path.basename(sys.argv[0]).replace(".py", "")
  try:
    import plugins
    plugins_loaded = True
  except ImportError:
    logger.debug("No plugins detected. Skipping")
  if plugins_loaded:
    for plugin_importer, plugin_name, plugin_ispkg in pkgutil.iter_modules(plugins.__path__):
      if plugin_ispkg:
        plugin_package = importlib.import_module("plugins.{}".format(plugin_name))
        for importer, modname, ispkg in pkgutil.iter_modules(plugin_package.__path__):
          plugin_module = importlib.import_module("plugins.{}.{}".format(plugin_name, modname))
          for name, obj in inspect.getmembers(plugin_module):
            if inspect.isclass(obj) and obj.__name__ == "EFPlugin":
              plugin = getattr(plugin_module, name)(context=context_obj)
              if plugin.service == service_name:
                try:
                  plugin.run()
                except AttributeError:
                  logger.error("Plugin '{}' is missing run method".format(modname))
