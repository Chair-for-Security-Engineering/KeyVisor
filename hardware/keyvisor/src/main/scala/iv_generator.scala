/**
    Hardware Description of KeyVisor -  A Lightweight ISA Extension for Protected Key Handles with CPU-enforced Usage Policies
    Author:     ********* (Blinded)
    Contact:    ********* (Blinded)

    To be used with Chipyard 1.10.0

    This code provides a proof-of-concept implementation of KeyVisor for the RocketChip RISC-V CPU.
    DO NOT use this code in productive environments! 
*/

package keyvisor

import Chisel._
import chisel3.util.{HasBlackBoxResource,Reverse,UIntToOH}
import chisel3.experimental.ChiselEnum
import freechips.rocketchip.tile._
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.rocket._
import keyvisor.common._

class IVGenIO()(implicit val p: Parameters) extends Bundle {
    val enable = Input(Bool())
    // val done = Output(Bool())
    val iv  = Output(Bits(width=96))
}

class IVGen()(implicit val p: Parameters) extends Module {
    val io = IO(new IVGenIO())
    
    // object CtrlState extends ChiselEnum {
    //     val sIdle, sGenIV = Value
    // }
    // val cstate = RegInit(CtrlState.sIdle)

    val lfsr = Module(new Lfsr96)

    // default assignments
    // io.done := false.B

    // when(cstate === CtrlState.sIdle){
    //     when(io.enable === true.B){
    //         cstate := CtrlState.sGenIV
    //     }
    // }
    io.iv := lfsr.io.y
    when(io.enable){
        lfsr.io.enable := true.B
    }.otherwise{
        lfsr.io.enable := false.B
    }
        
    //     io.done := true.B
    //     cstate := CtrlState.sIdle
    // }    

}