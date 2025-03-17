//see LICENSE for license
package rocketchip

import Chisel._
import uncore._
import rocket._
//import cde._
import cde.{Parameters, Field, Config, Knob, Dump, World, Ex, ViewSym}
import cde.Implicits._
import keyvisor._


class WithAESAccelerator extends Config((site, here, up) => {
  case BuildRoCC => Seq((p: Parameters) => LazyModule(
    new AESAccelerator(OpcodeSet.custom0)(p)))
})

class AESAcceleratorConfig extends Config(
  new WithAESAccelerator ++
  new RocketConfig)
