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
import chisel3.ChiselEnum
import freechips.rocketchip.tile._
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.rocket._
import keyvisor.common._

class MemData extends Bundle {
    val satp = UInt(64.W)
    val ctr = UInt(8.W)
    val valid = Bool()
}

class HandleCacheIO()(implicit val p: Parameters) extends Bundle with HasCoreParameters{
    val enable = Input(Bool())
    val write = Input(Bool())
    val iv = Input(UInt(96.W))
    val dIN = Input(new MemData)
    val dOUT = Output(new MemData)
    val xcpt = Output(Bool())
}



class HandleCache()(implicit val p: Parameters) extends Module  with HasCoreParameters{
    // 2-way, 64-set Handle Cache Buffer (HCB)
    val io = IO(new HandleCacheIO())
    // val row_buffer = Reg(new MemData)

    val TAG_HIGH: Int = 161
    val TAG_LOW: Int = 72
    val CTR_HIGH: Int  = 71
    val CTR_LOW: Int  = 64
    val SATP_HIGH: Int  = 63
    val SATP_LOW: Int  = 0

    object CtrlState extends ChiselEnum {
        val sIdle, sLoad, sWrite0, sWrite1 = Value
    }
    val cstate = RegInit(CtrlState.sIdle)

    io.xcpt := false.B

    val way0 = Module(new RWSmem)
    val way0_valid = RegInit(Vec(Seq.fill(64)(false.B))) // Create the valid register for way 0
    val way1 = Module(new RWSmem)
    val way1_valid = RegInit(Vec(Seq.fill(64)(false.B))) // Create the valid register for way 1

    val idx = Reg(UInt(6.W))
    val tag = Reg(UInt(90.W))
    val write = Reg(Bool())
    val dIN = Reg(UInt(162.W))
    val valid = Reg(Bool())

    
    way0.io.enable := false.B
    way0.io.dataIn := dIN
    way1.io.enable := false.B
    way1.io.dataIn := dIN

    when(cstate === CtrlState.sIdle){
        when(io.enable) {
            // store idx and tag in buffer
            tag := io.iv(95, 6)
            idx := io.iv(5, 0)
            write := io.write
            dIN := Cat(io.iv(95, 6), io.dIN.ctr, io.dIN.satp)
            valid := io.dIN.valid

            // Read the cache line to match the IV
            way0.io.addr := io.iv(5, 0)
            way0.io.write := false.B
            way0.io.enable:= true.B
            way1.io.addr := io.iv(5, 0)
            way1.io.write := false.B
            way1.io.enable:= true.B
            
            cstate := CtrlState.sLoad
        }
    }

    when(cstate === CtrlState.sLoad){
        // Way 0 Hit
        when(way0.io.dataOut(TAG_HIGH, TAG_LOW) === tag){
            // printf("HCB hit in way 0\n")
            when(write === false.B){
                io.dOUT.satp := way0.io.dataOut(SATP_HIGH, SATP_LOW)
                io.dOUT.ctr := way0.io.dataOut(CTR_HIGH, CTR_LOW)
                io.dOUT.valid := way0_valid(idx)
                cstate := CtrlState.sIdle
            }.otherwise{
                cstate := CtrlState.sWrite0
            }
        }
        // Way 1 Hit 
        when(way1.io.dataOut(TAG_HIGH, TAG_LOW) === tag){
            // printf("HCB hit in way 1\n")
            when(write === false.B){
                io.dOUT.satp := way1.io.dataOut(SATP_HIGH, SATP_LOW)
                io.dOUT.ctr := way1.io.dataOut(CTR_HIGH, CTR_LOW)
                io.dOUT.valid := way1_valid(idx)
                cstate := CtrlState.sIdle
            }.otherwise{
                cstate := CtrlState.sWrite1
            }
        }
        
        // MISS
        when(way0.io.dataOut(TAG_HIGH, TAG_LOW) =/= tag && way1.io.dataOut(TAG_HIGH, TAG_LOW) =/= tag){
            // printf("HCB Miss, idx: %d\n", idx)
            when(write === false.B){
                // io.dOUT.satp := way1.io.dataOut(SATP_HIGH, SATP_LOW)
                // io.dOUT.ctr := way1.io.dataOut(CTR_HIGH, CTR_LOW)
                io.dOUT.valid := false.B
                cstate := CtrlState.sIdle
            }.otherwise{
                when(way0_valid(idx) === true.B && way1_valid(idx) === true.B){
                    io.xcpt := true.B
                    // printf("HCB FULL Error\n")
                    cstate := CtrlState.sIdle
                }
                when(way0_valid(idx) === false.B){
                    cstate := CtrlState.sWrite0
                }.elsewhen (way1_valid(idx) === false.B){
                    cstate := CtrlState.sWrite1
                }
            }
        }
    }

    when(cstate === CtrlState.sWrite0){
        // printf("HCB Write to way 0\n")
        way0_valid(idx) := valid
        way0.io.enable := true.B
        way0.io.write := true.B
        way0.io.addr := idx

        cstate := CtrlState.sIdle
    }

    when(cstate === CtrlState.sWrite1){
        // printf("HCB write to way 1\n")
        way1_valid(idx) := valid
        way1.io.enable := true.B
        way1.io.write := true.B
        way1.io.addr := idx

        cstate := CtrlState.sIdle
    }
}