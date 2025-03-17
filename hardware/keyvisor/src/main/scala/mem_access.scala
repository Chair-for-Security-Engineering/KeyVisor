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
import chisel3.ChiselEnum
import freechips.rocketchip.tile._
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.rocket._
import keyvisor.common._

class MemAccessIOSmall()(implicit val p: Parameters) extends Bundle with HasCoreParameters{
    val enable = Input(Bits(width = 2))
    val dprv = Input(UInt(PRV.SZ.W))
    val dv = Input(Bool())
    val address1 = Input(UInt(coreMaxAddrBits.W))
    val address2 = Input(UInt(coreMaxAddrBits.W))
    val len1 = Input(UInt(width=7))
    val len2 = Input(UInt(width=7))
    val load_store = Input(Bool()) // Load = 0, Store = 1
    val input1 = Input(Bits(width=64))
    val input2 = Input(Bits(width=64))
    val output1 = Output(Bits(width=64))
    val output2 = Output(Bits(width=64))
    val exception = Output(Bool())
    val busy = Output(Bool())
    val done = Output(Bool())
    val ready = Output(Bool())
}

class MemAccessIO()(implicit val p: Parameters) extends Bundle with HasCoreParameters{
    val mem = new HellaCacheIO
    
    val ports = new MemAccessIOSmall
}

class MemAccess()(implicit val p: Parameters) extends Module{
    val io = IO(new MemAccessIO())
    
    object CtrlState extends ChiselEnum {
        val sIdle, sMemAccess, sWait = Value
    }
    val cstate = RegInit(CtrlState.sIdle)

    // MemAccess Registers
    val valid = Reg(Bits(width = 2), init = 0.U)
    val buf_reg1 = Reg(Bits(width = 64))
    val buf_reg2 = Reg(Bits(width = 64))
    val addr1 = Reg(Bits(width=64))
    val addr2 = Reg(Bits(width=64))
    val done = Reg(Bool(), init = false.B)
    val load_store = Reg(Bool())
    val task = Reg(Bits(width=2))
    val timeout = Reg(Bits(width=10))
    val bytes_processed = Reg(Bits(width = 4))

    val load_tag_ctr = RegInit(UInt(width = 8), 0.U)
    val store_tag_ctr  = RegInit(UInt(width = 8), 16.U)
    val store_complete_ctr  = RegInit(UInt(width = 8), 16.U)
    val pending_requests = RegInit(Vec(Seq.fill(16)(false.B)))

    // Wires
    val busy = Wire(Bool())
    val load_size = Wire(Bits(width = 2))
    val offset = Wire(Bits(width = 3))
    load_size := 0.U
    busy := (pending_requests.asUInt =/= 0.U || store_tag_ctr =/= store_complete_ctr || cstate =/= CtrlState.sIdle)

    when(~busy){
        store_tag_ctr := 16.U
        store_complete_ctr := 16.U
    }
    // Default Assignments

    io.mem.s1_kill := false.B
    io.mem.s2_kill := false.B
    io.mem.req.valid := false.B
    io.mem.req.bits.dprv := io.ports.dprv
    io.mem.req.bits.dv := io.ports.dv
    io.mem.req.bits.signed := false.B
    io.mem.req.bits.phys := false.B

    io.ports.output1 := buf_reg1
    io.ports.output2 := buf_reg2
    io.ports.done := done
    io.ports.ready := (cstate === CtrlState.sIdle)
    io.ports.busy := busy
    io.ports.exception := false.B

    
    io.mem.req.bits.addr := addr1
    io.mem.req.bits.data := ((buf_reg1 >> (bytes_processed << 3.U)) & createBitmask2((1.U << load_size) << 3.U)) << (offset << 3.U)

    // 128 Bit load / store unit
    when(cstate === CtrlState.sIdle){
        done := false.B
        timeout := 0.U
        when(io.ports.enable =/= "b00".U){
            midas.targetutils.SynthesizePrintf(printf("[MAccess] Enabled with input %d. Addr 1: %x, Addr 2: %x, Store? %d, D1: %x, D2: %x\n", io.ports.enable, io.ports.address1, io.ports.address2, io.ports.load_store,io.ports.input1, io.ports.input2))
            task := io.ports.enable
            addr1 := io.ports.address1
            addr2 := io.ports.address2
            load_store := io.ports.load_store

            when(io.ports.load_store === false.B){
                buf_reg1 := 0.U
                buf_reg2 := 0.U
            }.otherwise{
                buf_reg1 := io.ports.input1
                buf_reg2 := io.ports.input2
            }
            

            bytes_processed := 0.U

            cstate := CtrlState.sMemAccess                
        }
    }



    when(cstate === CtrlState.sMemAccess){
        offset := addr1 & 0x7.U

        switch(offset) {
            is(0.U){
                when(bytes_processed === 0.U){
                    load_size := 3.U // 64 Bit
                }.elsewhen(bytes_processed <= 4.U){
                    load_size := 2.U // 32 Bit
                }.elsewhen(bytes_processed <= 6.U){
                    load_size := 1.U // 16 Bit
                }.otherwise{
                    load_size := 0.U // 8 Bit
                }
            }
            is(1.U){
                // Since the address is not aligned, we can max load 1 byte
                load_size := 0.U // 8 Bit
            }
            is(2.U){
                when(bytes_processed === 7.U){
                    load_size := 0.U // 8 Bit
                }.otherwise{
                    load_size := 1.U // 16 Bit
                }
            }
            is(3.U){
                // Since the address is not aligned, we can max load 1 byte
                load_size := 0.U // 8 Bit
            }
            is(4.U){
                when(bytes_processed <= 4.U){
                    load_size := 2.U // 32 Bit
                }.elsewhen(bytes_processed <= 6.U){
                    load_size := 1.U // 16 Bit
                }.otherwise{
                    load_size := 0.U // 8 Bit
                }
            }
            is(5.U){
                // Since the address is not aligned, we can max load 1 byte
                load_size := 0.U // 8 Bit
            }
            is(6.U){
                when(bytes_processed <= 6.U){
                    load_size := 1.U // 16 Bit
                }.otherwise{
                    load_size := 0.U // 8 Bit
                }
            }
            is(7.U){
                // Since the address is not aligned, we can max load 1 byte
                load_size := 0.U // 8 Bit
            }
        }

        io.mem.req.bits.size := load_size
        io.mem.req.valid := true.B
        io.mem.req.bits.cmd := Mux(load_store, M_XWR, M_XRD)
        io.mem.req.bits.tag := Mux(load_store, store_tag_ctr, load_tag_ctr)
        
        when(io.mem.req.fire){
            when(load_store === false.B){
                midas.targetutils.SynthesizePrintf(printf("[MAccess] Request is firing, Store? %d, addr: %x, tag: %d, size: %d, bytes_processed: %d.\n", load_store, addr1, load_tag_ctr, load_size, bytes_processed))
                
                pending_requests(load_tag_ctr) := 1.U
                load_tag_ctr := load_tag_ctr + (1.U << load_size)
            }.otherwise{
                midas.targetutils.SynthesizePrintf(printf("[MAccess] Request is firing, Store? %d, addr: %x, tag: %d, size: %d, bytes_processed: %d, data %x.\n", load_store, addr1, store_tag_ctr, load_size, bytes_processed, buf_reg1))
                
                store_tag_ctr := store_tag_ctr + 1.U
            }

            

            when(bytes_processed + (1.U << load_size) === 8.U){
                bytes_processed := 0.U
                when(task === "b11".U){
                    task := "b10".U
                    addr1 := addr2
                    when(load_store === true.B){
                        buf_reg1 := buf_reg2
                    }
                }.otherwise{
                    when(load_store === true.B){
                        done := true.B
                        cstate := CtrlState.sIdle
                    }.otherwise{
                        cstate := CtrlState.sWait
                    }
                    
                }
            }.otherwise{        
                addr1 := addr1 + (1.U << load_size)
                bytes_processed := bytes_processed + (1.U << load_size)
            }
        }
    }


    when(cstate === CtrlState.sWait){
        when(pending_requests.asUInt === 0.U){
            done := true.B
            load_tag_ctr := 0.U
            cstate := CtrlState.sIdle
        }
    }

    when((busy) && io.mem.resp.valid){
        timeout := 0.U
        midas.targetutils.SynthesizePrintf(printf("[MAccess] Response is valid, tag: %d, size: %d, Has Data? %d, Data: %x.\n", io.mem.resp.bits.tag, io.mem.resp.bits.size, io.mem.resp.bits.has_data, io.mem.resp.bits.data))
        
        
        // Load operation, tag ist below 16
        when (io.mem.resp.bits.has_data){
            pending_requests(io.mem.resp.bits.tag) := 0.U
            when(io.mem.resp.bits.tag < 8.U){
                buf_reg1 := buf_reg1 | (io.mem.resp.bits.data << (io.mem.resp.bits.tag << 3.U))
            }.otherwise{
                buf_reg2 := buf_reg2 | (io.mem.resp.bits.data << ((io.mem.resp.bits.tag - 8.U) << 3.U))
            }
        }.otherwise{
            store_complete_ctr := store_complete_ctr + 1.U
            //store_tag_ctr := store_tag_ctr - 1.U
        }
    }

    when(busy){
        timeout := timeout + 1.U // The timeout occurs if the address provided was invalid
        //midas.targetutils.SynthesizePrintf(printf("[MAccess] timeout is %d\n", timeout))
        val ex = Wire(Bool())
        ex := io.mem.resp.bits.replay | io.mem.s2_nack | io.mem.replay_next | io.mem.s2_xcpt.ma.ld | io.mem.s2_xcpt.pf.ld | io.mem.s2_xcpt.gf.ld | io.mem.s2_xcpt.ae.ld | io.mem.s2_xcpt.ma.st | io.mem.s2_xcpt.pf.st | io.mem.s2_xcpt.gf.st | io.mem.s2_xcpt.ae.st | io.mem.s2_gpa_is_pte
        when(ex || (timeout === 1023.U)){
            midas.targetutils.SynthesizePrintf(printf("[MAccess] Exception occured %d\n", Cat(io.mem.resp.bits.replay,io.mem.s2_nack ,io.mem.replay_next, io.mem.s2_xcpt.ma.ld, io.mem.s2_xcpt.pf.ld, io.mem.s2_xcpt.gf.ld, io.mem.s2_xcpt.ae.ld, io.mem.s2_xcpt.ma.st, io.mem.s2_xcpt.pf.st, io.mem.s2_xcpt.gf.st, io.mem.s2_xcpt.ae.st, io.mem.s2_gpa_is_pte)))
            midas.targetutils.SynthesizePrintf(printf("Busy reason: %d\n", Cat(pending_requests.asUInt =/= 0.U,store_tag_ctr =/= store_complete_ctr, cstate =/= CtrlState.sIdle)))
            store_tag_ctr := 16.U
            store_complete_ctr := 16.U
            io.ports.exception := true.B
            cstate := CtrlState.sIdle
        }
    }

    
}