import importlib
import inspect
import logging
import os
import pkgutil
import sys

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
      """
      Base class of ef-plugins. Defines which service is extended and provides access to the current instance of
      EFContext to the plugin.

      Args:
        context (obj:EFContext): Instance of EFContext created by ef-open command line tool
        clients (dict): Dictionary of boto3 clients created by ef_utils.create_aws_clients()
      """

      def __init__(self, context, clients):
        self.service = service_name
        self.context = context
        self.clients = clients
        self.oInstance = cls()

      def __getattribute__(self, s):
        """
        This is called whenever any attribute of a EFPlugin object is accessed. This function first tries to
        get the attribute off EFPlugin. If it fails then it tries to fetch the attribute from self.oInstance
        (an instance of the decorated class).
        """
        try:
          x = super(EFPlugin, self).__getattribute__(s)
        except AttributeError:
          pass
        else:
          return x
        return self.oInstance.__getattribute__(s)

    return EFPlugin

  return class_rebuilder


def run_plugins(context_obj, boto3_clients):
  """
  Executes all loaded plugins designated for the service calling the function.

  Args:
    context_obj (obj:EFContext): The EFContext object created by the service.
    boto3_clients (dict): Dictionary of boto3 clients created by ef_utils.create_aws_clients()
  """

  def print_if_verbose(message):
    if context_obj.verbose:
      print(message)

  service_name = os.path.basename(sys.argv[0]).replace(".py", "")
  try:
    import plugins
  except ImportError:
    print_if_verbose("no plugins detected.")
    return
  else:
    for plugin_importer, plugin_name, plugin_ispkg in pkgutil.iter_modules(plugins.__path__):
      if plugin_ispkg:
        plugin_package = importlib.import_module("plugins.{}".format(plugin_name))
        for importer, modname, ispkg in pkgutil.iter_modules(plugin_package.__path__):
          plugin_module = importlib.import_module("plugins.{}.{}".format(plugin_name, modname))
          for name, obj in inspect.getmembers(plugin_module):
            if inspect.isclass(obj) and obj.__name__ == "EFPlugin":
              plugin_class = getattr(plugin_module, name)
              plugin_instance = plugin_class(context=context_obj, clients=boto3_clients)
              if plugin_instance.service == service_name:
                print_if_verbose("plugin '{}' loaded".format(plugin_name))
                if not context_obj.commit:
                  print_if_verbose("dryrun: skipping plugin execution.")
                else:
                  try:
                    plugin_instance.run()
                  except AttributeError:
                    print("error executing plugin '{}'".format(modname))
