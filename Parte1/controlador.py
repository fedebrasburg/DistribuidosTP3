def launch ():
  import pox.log.color
  pox.log.color.launch()
  import pox.log
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                        "@@@bold%(message)s@@@normal")
  from pox.core import core
  import pox.openflow.discovery
  pox.openflow.discovery.launch()

  core.getLogger("openflow.spanning_tree").setLevel("INFO")
  import pox.forwarding.l2_learning as fw
  core.getLogger().debug("Using forwarding: %s", fw.__name__)
  fw.launch()

  import pox.openflow.spanning_tree
  pox.openflow.spanning_tree.launch()
