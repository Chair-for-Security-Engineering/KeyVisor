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

class EncDecUnitIO()(implicit val p: Parameters) extends Bundle with HasCoreParameters{
    val enable = Input(Bool())
    val addr1 = Input(UInt(coreMaxAddrBits.W))
    val addr2 = Input(UInt(coreMaxAddrBits.W))
    val dprv = Input(UInt(PRV.SZ.W))
    val dv = Input(Bool())
    val wrappedKey = Input(UInt(128.W))
    val encdec = Input(Bool())
    
    val done = Output(Bool())
    val retVal = Output(UInt(4.W))
    // AES
    val aes = Flipped(new AESCoreIO)
    // Memory
    val maccess = Flipped(new MemAccessIOSmall)
    // IV GEN
    val genIV = Flipped(new IVGenIO)
}

class EncDecUnit()(implicit val p: Parameters) extends Module with HasCoreParameters{
    val io = IO(new EncDecUnitIO())

    object CtrlState extends ChiselEnum {
        val sIdle, sStart, sGenIV, sLoadIV, sLoadInLen, sLoadIOAddrs, sDoAESAAD, sDoAESData, sWaitForAES, sLoadNext, sStoreAESData, sStoreAESDataShort, sEndAES, sCompareTag, sFinish, sWaitForMem = Value
    }
    val cstate = RegInit(CtrlState.sIdle)

    val len_aad = Reg(UInt(width = 16))
    val len_data = Reg(UInt(width = 16))
    val load_ctr = Reg(UInt(width=14))
    val store_ctr = Reg(UInt(width=14))
    val delay = Reg(Bool())
    val aad_addr = Reg(UInt(width = coreMaxAddrBits))
    val data_addr = Reg(UInt(width = coreMaxAddrBits))
    val ret_val = Reg(UInt(4.W))
    val tag_buf = Reg(UInt(128.W))

    // Default AES
    io.aes.aes_gcm_icb_stop_cnt_i := false.B
    io.aes.aes_gcm_mode_i := 0.U // AES 128 (other variants are not available in BB currently)
    io.aes.aes_gcm_key_word_val_i := 0.U
    io.aes.aes_gcm_iv_val_i := false.B
    io.aes.aes_gcm_ghash_pkt_val_i := false.B
    io.aes.aes_gcm_ghash_aad_bval_i := "b0000".asUInt
    io.aes.aes_gcm_data_in_bval_i := "b0000".asUInt
    io.aes.aes_gcm_enc_dec_i := io.encdec
    io.aes.aes_gcm_icb_start_cnt_i := false.B
    io.aes.rst_i := false.B
    io.aes.aes_gcm_pipe_reset_i := false.B

    // Default Mem
    io.maccess.enable := "b00".U
    io.maccess.dprv :=  io.dprv
    io.maccess.dv := io.dv

    // Default IVGen 
    io.genIV.enable := false.B

    io.done := false.B

    when (cstate === CtrlState.sIdle){
        when(io.enable === true.B){
            load_ctr := 0.U
            store_ctr := 0.U
            delay := false.B
            cstate := CtrlState.sStart
        }
    }

    when (cstate === CtrlState.sStart && io.maccess.ready){
        midas.targetutils.SynthesizePrintf(printf("[ENCDEC] ENCDEC Unit started\n"))
        io.maccess.address1 := io.addr1 + 48.U
        io.maccess.load_store := 0.U
        io.maccess.enable := "b01".U
        
        // Init AES Key
        io.aes.aes_gcm_key_word_i := (io.wrappedKey << 128)
        io.aes.aes_gcm_key_word_val_i := 4.U

        cstate := CtrlState.sLoadInLen
    }

    when (cstate === CtrlState.sLoadInLen){
        when(io.maccess.done === true.B){
            len_aad := io.maccess.output1(15,0)
            len_data := io.maccess.output1(47,32)
            midas.targetutils.SynthesizePrintf(printf("[ENCDEC] AAD Lenght is %d, Data Lenght is %d\n", io.maccess.output1(15,0), io.maccess.output1(47,32)))
            when(io.encdec === false.B){
                cstate := CtrlState.sGenIV
            }.otherwise{
                io.maccess.address1 := io.addr1
                io.maccess.address2 := io.addr1 + 8.U 
                io.maccess.load_store := 0.U
                io.maccess.enable := "b11".U
                cstate := CtrlState.sLoadIV
            }
        }
    }

    when (cstate === CtrlState.sLoadIV){
        when (io.maccess.done === true.B){
            io.aes.aes_gcm_iv_i := Cat(io.maccess.output2(31,0), io.maccess.output1(63,0))
            io.aes.aes_gcm_iv_val_i := true.B
            io.aes.aes_gcm_icb_start_cnt_i := true.B

            io.maccess.enable := "b11".U
            io.maccess.load_store := false.B
            io.maccess.address1 := io.addr1 + 32.U 
            io.maccess.address2 := io.addr1 + 40.U 
            cstate := CtrlState.sWaitForAES
        }
    }

    when (cstate === CtrlState.sGenIV){
        midas.targetutils.SynthesizePrintf(printf("[ENCDEC] IV generated: %x\n", io.genIV.iv))
        io.genIV.enable := true.B
        io.aes.aes_gcm_iv_i := io.genIV.iv
        io.aes.aes_gcm_iv_val_i := true.B
        io.aes.aes_gcm_icb_start_cnt_i := true.B

        io.maccess.enable := "b11".U
        io.maccess.load_store := 1.U 
        io.maccess.input1 := io.genIV.iv(63,0)
        io.maccess.input2 := Cat(0.U, io.genIV.iv(95,64))
        io.maccess.address1 := io.addr1 //+ 4.U // Byte 16 ... 96
        io.maccess.address2 := io.addr1 + 8.U //+ 12.U // Byte 96 ... 128

        cstate := CtrlState.sLoadIOAddrs
    }

    when (cstate === CtrlState.sLoadIOAddrs && io.maccess.done === true.B){
        io.maccess.enable := "b11".U
        io.maccess.load_store := false.B
        io.maccess.address1 := io.addr1 + 32.U 
        io.maccess.address2 := io.addr1 + 40.U 
        cstate := CtrlState.sWaitForAES
    }

    when (cstate === CtrlState.sWaitForAES && io.maccess.ready && io.aes.aes_gcm_ready_o){
        midas.targetutils.SynthesizePrintf(printf("[ENCDEC] AES Unit is ready. Starting.\n"))
        midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Got IO Addresses. AAD: %x, DATA: %x\n", io.maccess.output1(coreMaxAddrBits-1, 0), io.maccess.output2(coreMaxAddrBits-1, 0)))

        aad_addr := io.maccess.output1(coreMaxAddrBits-1, 0)
        data_addr := io.maccess.output2(coreMaxAddrBits-1, 0)

        // In any case, we are loading data
        io.maccess.load_store := false.B

        when(len_aad === 0.U){
            // Directly start with AES Data.
            midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Skipping AAD.\n"))

            io.maccess.address1 := io.maccess.output2(coreMaxAddrBits-1, 0)
            
            //When loading more than 8 Bytes, load both values at the same time
            when(len_data > 8.U){
                io.maccess.address2 := io.maccess.output2(coreMaxAddrBits-1, 0) + 8.U 
                io.maccess.enable := "b11".U
            }.otherwise{
                io.maccess.enable := "b01".U
            }

            load_ctr := 2.U
            cstate := CtrlState.sDoAESData
        }.elsewhen(len_aad > 8.U){
            io.maccess.address1 := io.maccess.output1(coreMaxAddrBits-1, 0)
            
            
            io.maccess.address2 := io.maccess.output1(coreMaxAddrBits-1, 0) + 8.U
            io.maccess.enable := "b11".U
            load_ctr := 2.U
            cstate := CtrlState.sDoAESAAD
        }.otherwise{
            io.maccess.address1 := io.maccess.output1(coreMaxAddrBits-1, 0)
            midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Loading 8 Byte or less.\n"))
            io.maccess.enable := "b01".U
            load_ctr := 1.U
            cstate := CtrlState.sDoAESAAD
        }
    }

    when (cstate === CtrlState.sDoAESAAD) {
        io.aes.aes_gcm_ghash_pkt_val_i := true.B

        when(io.maccess.done === true.B){
            val aad_mask = Wire(UInt(128.W)) // There is a bug in the AES Implementation, requiring to set all unused bits of the AAD to 0
            
            when(len_aad <= 16.U){
                aad_mask := Fill(128, 1.U) & ~((1.U << ((16.U - len_aad(4,0))<<3.U))-1.U)
                

                io.aes.aes_gcm_ghash_aad_i := Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2)) & aad_mask
                io.aes.aes_gcm_ghash_aad_bval_i := Reverse(createBitmask(len_aad))//"hFFFF".asUInt

                midas.targetutils.SynthesizePrintf(printf("[ENCDEC] AAD MASK: %x, Len AAD: %d\n", aad_mask, len_aad))

                midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Feeding AAD: %x\n",Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2))& aad_mask))
                midas.targetutils.SynthesizePrintf(printf("[ENCDEC] BVAL AAD: %x\n",Reverse(createBitmask(len_aad))))
                midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Moving to Load Data.\n"))

                io.maccess.address1 := data_addr
                io.maccess.load_store := false.B
                when(len_data > 8.U){
                    io.maccess.address2 := data_addr + 8.U 
                    io.maccess.enable := "b11".U
                }.otherwise{
                    io.maccess.enable := "b01".U
                }

                load_ctr := 2.U
                cstate := CtrlState.sDoAESData
            }.otherwise{
                io.aes.aes_gcm_ghash_aad_i := Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2))
                io.aes.aes_gcm_ghash_aad_bval_i := Reverse(createBitmask(len_aad))//"hFFFF".asUInt
                midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Feeding AAD: %x\n",Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2))))
                midas.targetutils.SynthesizePrintf(printf("[ENCDEC] BVAL AAD: %x\n",Reverse(createBitmask(len_aad))))

                
                io.maccess.address1 := aad_addr + (load_ctr << 3.U)
                io.maccess.load_store := false.B
                when(len_aad > 24.U){
                    midas.targetutils.SynthesizePrintf(printf("[ENCDEC] AAD Len is %d. Loading next two words.\n", len_aad))
                    io.maccess.address2 := aad_addr + ((load_ctr + 1.U) << 3.U)
                    io.maccess.enable := "b11".U
                    load_ctr := load_ctr + 2.U
                }.otherwise{
                    // It hangs here, maybe it has to do with the TLB?
                    midas.targetutils.SynthesizePrintf(printf("[ENCDEC] AAD Len is %d. Loading next word.\n", len_aad))
                    io.maccess.enable := "b01".U
                    load_ctr := load_ctr + 1.U
                }
                
                len_aad := len_aad - 16.U
            }
        }       
    }

    when (cstate === CtrlState.sDoAESData) {
        io.aes.aes_gcm_ghash_pkt_val_i := true.B
        when(io.maccess.done === true.B){
            val data_mask = Wire(UInt(128.W)) // There is a bug in the AES Implementation, requiring to set all unused bits of the AAD to 0
            
            when(len_data < 16.U){
                data_mask := Fill(128, 1.U) & ~((1.U << ((16.U - len_data(3,0))<<3.U))-1.U) //((16.U - (len_data & b"1111")) << 3.U)
            }.otherwise{
                data_mask := Fill(128, 1.U)
            }
            

            io.aes.aes_gcm_data_in_i := Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2)) & data_mask
            io.aes.aes_gcm_data_in_bval_i := Reverse(createBitmask(len_data))//"hFFFF".asUInt
            midas.targetutils.SynthesizePrintf(printf("[ENCDEC] BVAL DATA: %x\n",Reverse(createBitmask(len_data))))
            midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Feeding DATA: %x\n",Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2))&data_mask))

            cstate := CtrlState.sStoreAESData
        }

    }

    when (cstate === CtrlState.sStoreAESData){
        io.aes.aes_gcm_ghash_pkt_val_i := true.B
        //assert(io.aes.aes_gcm_data_out_val_o === true.B, "AES Block should be valid here!")
        midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Got AES Out Block: %x \n", io.aes.aes_gcm_data_out_o))
        
        when(len_data >= 16.U){
            io.maccess.address1 := data_addr + (store_ctr << 3.U) 
            io.maccess.address2 := data_addr + ((store_ctr + 1.U) << 3.U) 
            io.maccess.load_store := true.B
            io.maccess.input2 := swapEndiannes(io.aes.aes_gcm_data_out_o(63,0))
            io.maccess.input1 := swapEndiannes(io.aes.aes_gcm_data_out_o(127,64))
            io.maccess.enable := "b11".U
            store_ctr := store_ctr + 2.U
            cstate := CtrlState.sLoadNext
        }.otherwise{
            // Load the existing data and mask it correctly
            printf("[Enc Dec Unit] Found uneven blocklength with len %d.\n", len_data)
            io.maccess.address1 := data_addr + (store_ctr << 3.U) 
            io.maccess.address2 := data_addr + ((store_ctr + 1.U) << 3.U) 
            io.maccess.load_store := false.B
            io.maccess.enable := "b11".U
            cstate := CtrlState.sStoreAESDataShort
        }        
    }

    when(cstate === CtrlState.sStoreAESDataShort){
        io.aes.aes_gcm_ghash_pkt_val_i := true.B
        when(io.maccess.done === true.B){
            val bm = Wire(Bits(width=64))
            when(len_data > 8.U){
                io.maccess.address1 := data_addr + (store_ctr << 3.U) 
                io.maccess.address2 := data_addr + ((store_ctr + 1.U) << 3.U) 
                io.maccess.load_store := true.B
                io.maccess.input1 := swapEndiannes(io.aes.aes_gcm_data_out_o(127,64))
                
                bm := Reverse(createBitmask2(8.U-(len_data(2, 0)) << 3.U))

                printf("Bitmask is:      %x\n", bm) 
                printf("AES Out Block:   %x\n", swapEndiannes(io.aes.aes_gcm_data_out_o(63,0)))
                printf("Memory Contents: %x\n", io.maccess.output2)
                printf("Store data is:   %x\n", swapEndiannes(io.aes.aes_gcm_data_out_o(63,0)) ^ (io.maccess.output2 & bm))

                io.maccess.input2 := swapEndiannes(io.aes.aes_gcm_data_out_o(63,0)) ^ (io.maccess.output2 & bm)
                io.maccess.enable := "b11".U
            }.elsewhen(len_data === 8.U){
                io.maccess.address1 := data_addr + (store_ctr << 3.U) 
                io.maccess.load_store := true.B
                io.maccess.input1 := swapEndiannes(io.aes.aes_gcm_data_out_o(127,64))
                io.maccess.enable := "b01".U
            }.otherwise{
                io.maccess.address1 := data_addr + (store_ctr << 3.U) 
                io.maccess.load_store := true.B

                bm := Reverse(createBitmask2(8.U-(len_data(2, 0)) << 3.U))
                io.maccess.input1 := swapEndiannes(io.aes.aes_gcm_data_out_o(127,64)) ^ (io.maccess.output1 & bm)

                printf("Bitmask is:      %x\n", bm) 
                printf("AES Out Block:   %x\n", swapEndiannes(io.aes.aes_gcm_data_out_o(127,64)))
                printf("Memory Contents: %x\n", io.maccess.output2)
                printf("Store data is:   %x\n", swapEndiannes(io.aes.aes_gcm_data_out_o(127,64)) ^ (io.maccess.output1 & bm))

                io.maccess.enable := "b01".U
            }
            cstate := CtrlState.sWaitForMem
        }
        
    }

    when(cstate === CtrlState.sWaitForMem ){
        io.aes.aes_gcm_ghash_pkt_val_i := true.B
        when(io.maccess.busy === false.B){
            cstate := CtrlState.sEndAES
        }
        
    }

    when(cstate === CtrlState.sLoadNext){
        io.aes.aes_gcm_ghash_pkt_val_i := true.B
        when(io.maccess.busy === false.B && io.aes.aes_gcm_ready_o === true.B){ // Check for AES ready is only needed with XS AES core.
            when(len_data > 16.U){
                io.maccess.address1 := data_addr + (load_ctr << 3.U)
                io.maccess.load_store := false.B
                //printf("Attempting to read data from %x\n", data_addr + ((load_ctr + 1.U) << 3.U))
                when(len_data > 24.U){
                    io.maccess.address2 := data_addr + ((load_ctr + 1.U) << 3.U)
                    io.maccess.enable := "b11".U
                    
                    load_ctr := load_ctr + 2.U
                }.otherwise{
                    io.maccess.enable := "b01".U
                    load_ctr := load_ctr + 1.U
                }
                len_data := len_data - 16.U
                cstate := CtrlState.sDoAESData
            }.otherwise{
                cstate := CtrlState.sEndAES
            }
        }
    }

    when (cstate === CtrlState.sEndAES){
        when(io.aes.aes_gcm_ghash_tag_val_o){
            midas.targetutils.SynthesizePrintf(printf("[ENCDEC] Got AES TAG: %x \n", io.aes.aes_gcm_ghash_tag_o))
            tag_buf := io.aes.aes_gcm_ghash_tag_o
            when(io.encdec === false.B){
                io.maccess.address1 := io.addr1 + 16.U
                io.maccess.address2 := io.addr1 + 24.U
                io.maccess.load_store := true.B
                io.maccess.input2 := swapEndiannes(io.aes.aes_gcm_ghash_tag_o(63,0))
                io.maccess.input1 := swapEndiannes(io.aes.aes_gcm_ghash_tag_o(127,64))
                io.maccess.enable := "b11".U
                ret_val := 0.U
                cstate := CtrlState.sFinish
            }.otherwise{
                io.maccess.address1 := io.addr1 + 16.U
                io.maccess.address2 := io.addr1 + 24.U
                io.maccess.load_store := false.B
                io.maccess.enable := "b11".U
                cstate := CtrlState.sCompareTag
            }
        }
    }

    when (cstate === CtrlState.sCompareTag){
        when(io.maccess.done === true.B){
            midas.targetutils.SynthesizePrintf(printf("Comparing Tags, checking if %x == %x\n ", tag_buf, Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2))))
            when(tag_buf === Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2))){
                midas.targetutils.SynthesizePrintf(printf("Tag is valid.\n"))
                ret_val := 0.U
            }.otherwise{
                midas.targetutils.SynthesizePrintf(printf("Tag is invalid.\n"))
                ret_val := 4.U
            }
            cstate := CtrlState.sFinish
        }
        
    }

    when(cstate === CtrlState.sFinish && io.maccess.busy === false.B){
        io.aes.rst_i := true.B // Reset AES GCM STATE -- Maybe move this somewhere else`?
        io.aes.aes_gcm_pipe_reset_i := true.B
        io.done := true.B
        io.retVal := ret_val
        cstate := CtrlState.sIdle
    }

    when(io.maccess.exception === true.B){
        ret_val := 1.U
        cstate := CtrlState.sFinish
    }

}
