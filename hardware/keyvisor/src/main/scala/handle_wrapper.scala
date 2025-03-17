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
import keyvisor.common._
import freechips.rocketchip.tile._
import freechips.rocketchip.rocket._
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._

class PmpInfo()(implicit val p: Parameters) extends Bundle with HasCoreParameters{
    val addr = Vec(8,  UInt((paddrBits - PMP.lgAlign).W))
    val r = Vec(8,  Bool())
    val w = Vec(8,  Bool())
    val x = Vec(8,  Bool())
}

class HandleWrapperIO()(implicit val p: Parameters) extends Bundle with HasCoreParameters{
    val enable = Input(Bool())
    val encdec = Input(Bool()) // Enc=false, Dec = true
    val addr1 = Input(UInt(coreMaxAddrBits.W))
    val addr2 = Input(UInt(coreMaxAddrBits.W))
    val keyValid = Input(Bool())
    val CPUKey = Input(UInt(128.W))
    val dprv = Input(UInt(PRV.SZ.W))
    val dv = Input(Bool())
    val revoke = Input(Bool())
    val satp = Input(UInt(64.W))
    val done = Output(Bool())
    val allow_dec = Output(Bool())
    val allow_enc = Output(Bool())
    val retVal = Output(UInt(2.W))
    val wrappedKey = Output(UInt(128.W))
    // AES
    val aes = Flipped(new AESCoreIO)
    // Memory
    val maccess = Flipped(new MemAccessIOSmall)
    val hcb = Flipped(new HandleCacheIO)
    // GenIV
    val genIV = Flipped(new IVGenIO)
    // PTW
    val pmp = Input(new PmpInfo)
}

class HandleWrapper()(implicit val p: Parameters) extends Module with HasCoreParameters{
    val io = IO(new HandleWrapperIO())

    def createHandleLOW(pmp_bind : Bool, self_bind : Bool, enc : Bool, dec : Bool, lifetime : Bool, binding : Bool, usageCtr : Bool, prv : UInt): Bits = {
        val result = Wire(Bits(128.W))

        val handle_attrFlags = Wire(UInt(width = 8))
        val handle_privileges = Wire(UInt(width = 8))
        val handle_cryptoAlgo = Wire(UInt(width = 8))
        val handle_cryptoAttrs = Wire(UInt(width = 8))
        val handle_exattrMap = Wire(UInt(width = 16))
        val handle_reserverd16 = Wire(UInt(width = 16))
        val handle_timestamp = Wire(UInt(width = 64))
        handle_attrFlags := Cat(0.U, self_bind, pmp_bind) // TODO Should be reversed
        handle_privileges := prv
        handle_cryptoAlgo := 1.U
        handle_cryptoAttrs := Cat(dec, enc)
        handle_exattrMap := Cat(0.U, usageCtr, binding, lifetime)
        handle_reserverd16 := 0.U
        handle_timestamp := 0.U
        
        result := Cat(handle_timestamp, handle_reserverd16, handle_exattrMap, handle_cryptoAttrs, handle_cryptoAlgo, handle_privileges, handle_attrFlags)
        result
    }

    def createHandleHIGH(iv : UInt) : Bits = {
        val result = Wire(Bits(width = 128))

        val handle_IV = Wire(UInt(96.W))
        val handle_reserved = Wire(UInt(32.W))

        handle_IV := iv
        handle_reserved := 0.U
        
        result := Cat(handle_reserved, handle_IV)
        result
    }


    object CtrlState extends ChiselEnum {
        val sIdle, sStart, sStartAESModule, sLoadHandleMeta, sStoreHandle, sAADConsume1, sAADConsume2, sLoadPlain, sWaitForTag, sFinish, sCheckPermissions, sCheckPermissions2, sUpdateHandle, sLoadExternalBinding, sBindExternal = Value
    }
    val cstate = RegInit(CtrlState.sIdle)


    // Handle Enc Registers
    val ret_val = Reg(UInt(4.W))
    val wrapped_key = Reg(UInt(128.W))
    val encdec = Reg(Bool())
    val done = RegInit(Bool(), false.B)
    val valid = Reg(Bits(width = 2))

    // Handle Status Reg
    val allow_enc = Reg(Bool())
    val allow_dec = Reg(Bool())
    val en_binding = Reg(Bool())
    val en_usage_ctr = Reg(Bool())
    val en_lifetime = Reg(Bool())

    val handle_privs = Reg(UInt(8.W))
    val usage_ctr = Reg(UInt(8.W))
    val pmp_bind = Reg(Bool())
    val self_bind = Reg(Bool())

    // Wires
    val handle_low = Wire(UInt(128.W))
    val handle_high = Wire(UInt(128.W))

    // Default Assignments
    io.done := done //false.B
    io.retVal := ret_val
    io.wrappedKey := wrapped_key
    io.allow_dec := allow_dec
    io.allow_enc := allow_enc

    io.maccess.enable := "b00".U
    io.maccess.dprv :=  io.dprv
    io.maccess.dv := io.dv
    io.maccess.address1 := io.addr1
    io.maccess.address2 := io.addr2

    io.hcb.enable := false.B  
    io.hcb.write := false.B  
    io.hcb.dIN.satp := io.satp
    io.hcb.dIN.valid := false.B
    io.hcb.dIN.ctr := usage_ctr

    io.genIV.enable := false.B 

    io.aes.aes_gcm_icb_stop_cnt_i := false.B
    io.aes.aes_gcm_mode_i := 0.U // AES 128 (other variants are not available in BB currently)
    io.aes.aes_gcm_key_word_val_i := 0.U
    io.aes.aes_gcm_iv_val_i := false.B
    io.aes.aes_gcm_ghash_pkt_val_i := false.B
    io.aes.aes_gcm_ghash_aad_bval_i := "b0000".asUInt
    io.aes.aes_gcm_data_in_bval_i := "b0000".asUInt
    io.aes.aes_gcm_enc_dec_i := encdec
    io.aes.aes_gcm_icb_start_cnt_i := false.B
    io.aes.rst_i := false.B
    io.aes.aes_gcm_pipe_reset_i := false.B
    
    when (cstate === CtrlState.sIdle){
        done := false.B
        valid := 0.U
        ret_val := 0.U
        usage_ctr := 0.U
        when(io.enable === true.B){
            encdec := io.encdec
            cstate := CtrlState.sStart
        }
    }

    when (cstate === CtrlState.sStart){
        when(io.keyValid === false.B){
            midas.targetutils.SynthesizePrintf(printf("[HandleEnc] No CPU Key - error\n"))
            ret_val := 5.U
            cstate := CtrlState.sFinish
        }.otherwise{
            // Load the CPU Key to AES Module
            midas.targetutils.SynthesizePrintf(printf("[HandleEnc] Loading the CPU Key\n"))
            io.aes.aes_gcm_key_word_i := (io.CPUKey << 128)
            io.aes.aes_gcm_key_word_val_i := 4.U

            // Load Meta 
            when (encdec === false.B){
                io.maccess.address1 := io.addr1 + 16.U
                io.maccess.address2 := io.addr1 + 24.U
            }.otherwise{
                io.maccess.address1 := io.addr2 // handle
                io.maccess.address2 := io.addr2 + 8.U
            }
            io.maccess.load_store := 0.U
            io.maccess.enable := "b11".U

            cstate := CtrlState.sLoadHandleMeta
            
        }
    }


    when(cstate === CtrlState.sLoadHandleMeta){
        when(io.maccess.done === true.B){
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Handle Data loaded: %x %x\n", io.maccess.output1, io.maccess.output2))
            // Load the handle flags
            en_lifetime := io.maccess.output1(32)
            en_binding  := io.maccess.output1(33)
            en_usage_ctr := io.maccess.output1(34)
            
            allow_enc := io.maccess.output1(24)
            allow_dec := io.maccess.output1(25)

            when(encdec === false.B){
                // Set the privileges
                handle_privs := io.maccess.output1(7, 0)

                // Binding Mode
                self_bind := io.maccess.output1(54)
                pmp_bind := io.maccess.output1(55)


                // Encryption: Create the handle and store it to memory
                handle_low := createHandleLOW(io.maccess.output1(55), io.maccess.output1(54), io.maccess.output1(24), io.maccess.output1(25), io.maccess.output1(32), io.maccess.output1(33), io.maccess.output1(34), io.maccess.output1(7, 0))
                // Store Handle
                io.maccess.address1 := io.addr2
                io.maccess.address2 := io.addr2 + 8.U
                io.maccess.input1 := handle_low(63, 0)
                io.maccess.input2 := handle_low(127, 64)
                io.maccess.load_store := 1.U
                io.maccess.enable := "b11".U

                // Load the usage CTR from memory
                usage_ctr := io.maccess.output1(23, 16) // TODO
                midas.targetutils.SynthesizePrintf(printf("Handle attributes loaded. Lifetime: %d, Binding: %d, UsageCtr: %d (val: %d), Privs: %d, Enc: %d, Dec: %d, Self Bind: %d, Pmp Mode: %d\n", io.maccess.output1(32), io.maccess.output1(33), io.maccess.output1(34), io.maccess.output1(23, 16), io.maccess.output1(7, 0), io.maccess.output1(24), io.maccess.output1(25), io.maccess.output1(54), io.maccess.output1(55)))

                cstate := CtrlState.sStoreHandle
            }.otherwise{
                // Set handle Privileges 
                handle_privs := io.maccess.output1(15, 8)

                // Decryption: Load the IV from Memory
                io.maccess.address1 := io.addr2 + 16.U
                io.maccess.address2 := io.addr2 + 24.U
                io.maccess.load_store := 0.U
                io.maccess.enable := "b11".U

                cstate := CtrlState.sCheckPermissions
            }
            
        }
    }

    // -> sLoadHandleMeta (Only Encryption Path)
    when(cstate === CtrlState.sStoreHandle && io.maccess.ready){ 
        // Temporarily store the IV, we'll need it later on.
        io.genIV.enable := true.B // Shift LFSR
        wrapped_key := Cat(0.U, io.genIV.iv)

        // Load the IV to the AES Module
        printf("[HandleEnc] IV is %x\n",io.genIV.iv)
        io.aes.aes_gcm_iv_i := io.genIV.iv
        io.aes.aes_gcm_iv_val_i := true.B

        // Store the hadnle including the IV
        io.maccess.address1 := io.addr2 + 16.U
        io.maccess.address2 := io.addr2 + 24.U
        handle_high := createHandleHIGH(io.genIV.iv)
        io.maccess.input1 := handle_high(63, 0)
        io.maccess.input2 := handle_high(127, 64)
        io.maccess.load_store := 1.U
        io.maccess.enable := "b11".U


        when(en_binding === false.B || (en_binding === true.B && pmp_bind === false.B && self_bind === true.B)){
            // We can directly create an entry in the HCB and move on to start the encryption
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Binding to this Process, PID: %x\n", io.satp))

            io.genIV.enable := true.B
            io.hcb.enable := true.B
            io.hcb.write := true.B
            io.hcb.iv := io.genIV.iv
            io.hcb.dIN.ctr := usage_ctr
            io.hcb.dIN.satp := io.satp
            io.hcb.dIN.valid := true.B          

            midas.targetutils.SynthesizePrintf(printf("Store handle 1 done.\n"))
            cstate := CtrlState.sStartAESModule
        }.otherwise{
            when(self_bind === false.B){
                cstate := CtrlState.sLoadExternalBinding
            }.otherwise{
                midas.targetutils.SynthesizePrintf(printf("Binding to PMP\n"))
                // We are binding to the PMP ID -- Todo: Keystone seems to use TOR only. Check what happens when more than 3 Enclaves are active at the same time. Might switch to NAPOT then which is not compatible with the following matching technique
                val hit = Wire(Bool())
                hit:=false.B
                when((io.satp(43,0) << 10) > io.pmp.addr(1) && (io.satp(43,0) << 10) < io.pmp.addr(2)){
                    // PMP 2
                    midas.targetutils.SynthesizePrintf(printf("SATP is in PMP2\n"))
                    io.hcb.enable := true.B
                    io.hcb.write := true.B
                    io.genIV.enable := true.B
                    io.hcb.iv := io.genIV.iv
                    io.hcb.dIN.ctr := usage_ctr
                    io.hcb.dIN.satp := 2.U
                    io.hcb.dIN.valid := true.B    
                    hit := true.B
                }
                when((io.satp(43,0) << 10) > io.pmp.addr(3) && (io.satp(43,0) << 10) < io.pmp.addr(4)){
                    // PMP 4
                    midas.targetutils.SynthesizePrintf(printf("SATP is in PMP4\n"))
                    io.hcb.enable := true.B
                    io.hcb.write := true.B
                    io.genIV.enable := true.B
                    io.hcb.iv := io.genIV.iv
                    io.hcb.dIN.ctr := usage_ctr
                    io.hcb.dIN.satp := 4.U
                    io.hcb.dIN.valid := true.B    
                    hit := true.B
                }
                when((io.satp(43,0) << 10) > io.pmp.addr(5) && (io.satp(43,0) << 10) < io.pmp.addr(6)){
                    // PMP 6
                    midas.targetutils.SynthesizePrintf(printf("SATP is in PMP6\n"))
                    io.hcb.enable := true.B
                    io.hcb.write := true.B
                    io.genIV.enable := true.B
                    io.hcb.iv := io.genIV.iv
                    io.hcb.dIN.ctr := usage_ctr
                    io.hcb.dIN.satp := 6.U
                    io.hcb.dIN.valid := true.B 
                    hit := true.B
                }
                when(hit === true.B){
                    cstate := CtrlState.sStartAESModule
                }.otherwise{
                    midas.targetutils.SynthesizePrintf(printf("[Wrapkey] SATP did not match any PMP region (excluding 0 and 7)\n"))
                    ret_val := 1.U
                    cstate := CtrlState.sFinish
                }
                
            }
        }
    }

    when(cstate === CtrlState.sLoadExternalBinding && io.maccess.ready){
        io.maccess.address1 := io.addr1 + 32.U
        io.maccess.address2 := io.addr1 + 40.U
        io.maccess.load_store := 0.U
        io.maccess.enable := "b11".U

        cstate := CtrlState.sBindExternal
    }

    when(cstate === CtrlState.sBindExternal && io.maccess.done){
        // Write HCB entry and move on to start the encryption
        io.hcb.enable := true.B
        io.hcb.write := true.B
        io.hcb.iv := wrapped_key // The IV is temporarily stored here
        io.hcb.dIN.ctr := usage_ctr
        io.hcb.dIN.valid := true.B
        when(pmp_bind === false.B){
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Binding to external Process, PID: %x\n", io.maccess.output1))
            io.hcb.dIN.satp := io.maccess.output1
        }.otherwise{
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Binding to external Enclave, ID: %x\n", io.maccess.output2(7,0)))
            io.hcb.dIN.satp := Cat(0.U, io.maccess.output2(7,0))
        }
        cstate := CtrlState.sStartAESModule
    }

    // -> sLoadHandleMeta (Only Decryption Path)
    when(cstate === CtrlState.sCheckPermissions && io.maccess.ready){ 
        // Check if the provided IV is valid 
        io.hcb.enable := true.B
        io.hcb.write := false.B
        io.hcb.iv := Cat(io.maccess.output2(31,0), io.maccess.output1)

        // Load the IV to AES
        printf("[HandleEnc] IV is %x\n",Cat(io.maccess.output2(31,0), io.maccess.output1))
        io.aes.aes_gcm_iv_i := Cat(io.maccess.output2(31,0), io.maccess.output1)
        io.aes.aes_gcm_iv_val_i := true.B

        cstate := CtrlState.sCheckPermissions2
        
    }

    // -> sCheckPermissions; cpu mem output is now available
    when(cstate === CtrlState.sCheckPermissions2){
        // Check if the handle has a usage ctr
        when(en_usage_ctr){
            usage_ctr := io.hcb.dOUT.ctr
        }

        // midas.targetutils.SynthesizePrintf(printf("Handle attributes loaded. Lifetime: %d, Proc.Bind: %d, UsageCtr: %d (val: %d), Enc: %d, Dec: %d\n", en_lifetime, en_proc_bind, en_usage_ctr, io.hcb.dOUT.ctr, allow_enc, allow_dec))

        // Check if the handle is valid
        when(io.hcb.dOUT.valid =/= true.B || 
            (en_binding === true.B && (pmp_bind === false.B && io.hcb.dOUT.satp =/= io.satp)) || 
            (en_usage_ctr && io.hcb.dOUT.ctr === 0.U)){
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] The handle was Invalid! Valid? %d, Bind? %d, HCB SATP: %x, SATP: %x, UsageCtr? %d, Ctr: %d\n", io.hcb.dOUT.valid, pmp_bind, io.hcb.dOUT.satp, io.satp, en_usage_ctr, io.hcb.dOUT.ctr))
            ret_val := 3.U
            cstate := CtrlState.sFinish
        }.otherwise{
            when(en_binding === true.B && pmp_bind === true.B){
                val hit = Wire(Bool())
                hit := false.B
                when(io.hcb.dOUT.satp === 2.U && (io.satp(43,0) << 10) > io.pmp.addr(1) && (io.satp(43,0) << 10) < io.pmp.addr(2)){
                    // PMP 2
                    midas.targetutils.SynthesizePrintf(printf("[WrapKey] SATP matched in PMP2\n"))
                    hit := true.B
                }
                when(io.hcb.dOUT.satp === 4.U && (io.satp(43,0) << 10) > io.pmp.addr(3) && (io.satp(43,0) << 10) < io.pmp.addr(4)){
                    // PMP 4
                    midas.targetutils.SynthesizePrintf(printf("[WrapKey] SATP matched in PMP4\n"))
                    hit := true.B
                }
                when(io.hcb.dOUT.satp === 6.U && (io.satp(43,0) << 10) > io.pmp.addr(5) && (io.satp(43,0) << 10) < io.pmp.addr(6)){
                    // PMP 6
                    midas.targetutils.SynthesizePrintf(printf("[WrapKey] SATP matched in PMP6\n"))
                    hit := true.B
                }
                when(hit === true.B){
                    io.maccess.address1 := io.addr2 
                    io.maccess.address2 := io.addr2 + 8.U
                    io.maccess.load_store := 0.U
                    io.maccess.enable := "b11".U
                    cstate := CtrlState.sStartAESModule
                }.otherwise{
                    midas.targetutils.SynthesizePrintf(printf("[WrapKey] PMP Binding didn't match!\n"))
                    ret_val := 3.U
                    cstate := CtrlState.sFinish
                }
            }.otherwise{
                io.maccess.address1 := io.addr2 
                io.maccess.address2 := io.addr2 + 8.U
                io.maccess.load_store := 0.U
                io.maccess.enable := "b11".U
                cstate := CtrlState.sStartAESModule
            }
            
        }

        when(io.dprv === 0.U && handle_privs(0) =/= 1.U){ // User Mode
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] User Mode but Handle ist not allowed in User Mode (Privs: %x)\n", handle_privs))
            ret_val := 1.U
            cstate := CtrlState.sFinish
        }
        when(io.dprv === 1.U && handle_privs(1) =/= 1.U){ // Supervisor Mode
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Supervisor Mode but Handle ist not allowed in Supervisor Mode (Privs: %x)\n", handle_privs))
            ret_val := 1.U
            cstate := CtrlState.sFinish
        }
        when(io.dprv === 3.U && handle_privs(3) =/= 1.U){ // Machine Mode
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Machine Mode but Handle ist not allowed in Machine Mode (Privs: %x)\n", handle_privs))
            ret_val := 1.U
            cstate := CtrlState.sFinish
        }
    }

    // -> sStoreHandle
    when (cstate === CtrlState.sStartAESModule){
        // start icb counter
        io.aes.aes_gcm_icb_start_cnt_i := true.B
        cstate := CtrlState.sAADConsume1
    }

    
    // -> sStartAESModule
    when(cstate === CtrlState.sAADConsume1 && io.aes.aes_gcm_ready_o && io.maccess.ready){
        when(encdec === false.B){
            // Feed handle low to the AES module as AAD
            handle_low := createHandleLOW(pmp_bind, self_bind, allow_enc, allow_dec, en_lifetime, en_binding, en_usage_ctr, handle_privs)
            io.aes.aes_gcm_ghash_aad_i := handle_low // For WrapKey, AAD is 64 Bit
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] AAD 1 (HandleLow) is %x\n", handle_low))
            
            cstate := CtrlState.sAADConsume2
        }.otherwise{
            // Feed handle low to the AES module as AAD
            io.aes.aes_gcm_ghash_aad_i := Cat(io.maccess.output2, io.maccess.output1)
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] AAD 1 is %x\n", Cat(io.maccess.output2, io.maccess.output1)))

            // Load upper half of the handle
            io.maccess.address1 := io.addr2 + 16.U
            io.maccess.address2 := io.addr2 + 24.U
            io.maccess.load_store := 0.U
            io.maccess.enable := "b11".U

            cstate := CtrlState.sAADConsume2
        }
        io.aes.aes_gcm_ghash_aad_bval_i := Reverse(createBitmask(16.U & "b0000111111".U))//"hFFFF".asUInt
        io.aes.aes_gcm_ghash_pkt_val_i := true.B
        midas.targetutils.SynthesizePrintf(printf("[WrapKey] AAD Bitmask is %x\n", Reverse(createBitmask(16.U & "b0000111111".U))))  
    }

    when(cstate === CtrlState.sAADConsume2){io.aes.aes_gcm_ghash_pkt_val_i := true.B}
    when(cstate === CtrlState.sAADConsume2 && io.maccess.ready){
        when(encdec === false.B){
            // wrapped key contains the IV in the encryption path. After this, we don't need it anymore
            io.aes.aes_gcm_ghash_aad_i := createHandleHIGH(wrapped_key(95,0)) 
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] AAD 2 is %x\n", createHandleHIGH(wrapped_key(95,0))))

            // Load Key
            io.maccess.address1 := io.addr1
            io.maccess.address2 := io.addr1 + 8.U
            io.maccess.load_store := 0.U
            io.maccess.enable := "b11".U
        }.otherwise{
            io.aes.aes_gcm_ghash_aad_i := Cat(io.maccess.output2, io.maccess.output1)
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] AAD 2 is %x\n", Cat(io.maccess.output2, io.maccess.output1)))

            // Load CT
            io.maccess.address1 := io.addr2 + 48.U
            io.maccess.address2 := io.addr2 + 56.U
            io.maccess.load_store := 0.U
            io.maccess.enable := "b11".U
        }
        io.aes.aes_gcm_ghash_aad_bval_i := Reverse(createBitmask(16.U & "b0000111111".U))//"hFFFF".asUInt
        
        
        midas.targetutils.SynthesizePrintf(printf("[WrapKey] AAD Bitmask is %x\n", Reverse(createBitmask(16.U & "b0000111111".U))))
        cstate := CtrlState.sLoadPlain
    }

    when(cstate === CtrlState.sLoadPlain){
        io.aes.aes_gcm_ghash_pkt_val_i := true.B
        when(io.maccess.done === true.B){
            io.aes.aes_gcm_data_in_bval_i := Reverse(createBitmask(16.U & "b0000111111".U))//"hFFFF".asUInt
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Plaintext Bitmask is %x\n", Reverse(createBitmask(16.U & "b0000111111".U))))
            when(encdec === false.B){
                midas.targetutils.SynthesizePrintf(printf("[WrapKey] Wrapping Key %x %x\n", swapEndiannes(io.maccess.output1),swapEndiannes(io.maccess.output2)))
                io.aes.aes_gcm_data_in_i := Cat(swapEndiannes(io.maccess.output1), swapEndiannes(io.maccess.output2))
            }.otherwise{
                io.aes.aes_gcm_data_in_i := Cat(io.maccess.output1, io.maccess.output2)
                valid := 0.U
                io.maccess.address1 := io.addr2 + 32.U
                io.maccess.address2 := io.addr2 + 40.U
                io.maccess.load_store := 0.U
                io.maccess.enable := "b11".U
            }
            cstate := CtrlState.sWaitForTag
        }
    }

    when(io.aes.aes_gcm_data_out_val_o  && cstate =/= CtrlState.sIdle){
        midas.targetutils.SynthesizePrintf(printf("[WrapKey] Got AES output %x.\n", io.aes.aes_gcm_data_out_o))
        when(encdec === false.B){
            io.maccess.address1 := io.addr2 + 48.U
            io.maccess.address2 := io.addr2 + 56.U
            io.maccess.input2 := io.aes.aes_gcm_data_out_o(63,0)
            io.maccess.input1 := io.aes.aes_gcm_data_out_o(127,64)
            io.maccess.load_store := 1.U
            io.maccess.enable := "b11".U
        }.otherwise{
            midas.targetutils.SynthesizePrintf(printf("[WrapKey]Wrapped key is %x\n", io.aes.aes_gcm_data_out_o))
            wrapped_key := io.aes.aes_gcm_data_out_o // Decrypted Handle Key
        }
        
    }
    
    when(cstate === CtrlState.sWaitForTag){
        when(io.aes.aes_gcm_ghash_tag_val_o){
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Got AES TAG output %x.\n", io.aes.aes_gcm_ghash_tag_o))
            valid := valid | "b10".U
            when(encdec === false.B){
                io.maccess.address1 := io.addr2 + 32.U
                io.maccess.address2 := io.addr2 + 40.U
                io.maccess.input2 := io.aes.aes_gcm_ghash_tag_o(63,0)
                io.maccess.input1 := io.aes.aes_gcm_ghash_tag_o(127,64)
                io.maccess.load_store := 1.U
                io.maccess.enable := "b11".U

                ret_val := 0.U
                cstate := CtrlState.sFinish
            }
        }
        when(io.maccess.done === true.B){
            valid := valid | "b01".U
        }
        when(valid === "b11".U){
            midas.targetutils.SynthesizePrintf(printf("[WrapKey] Comparing Tags, checking if %x == %x\n ", io.aes.aes_gcm_ghash_tag_o, Cat(io.maccess.output1, io.maccess.output2)))
            when(io.aes.aes_gcm_ghash_tag_o === Cat(io.maccess.output1, io.maccess.output2)){
                midas.targetutils.SynthesizePrintf(printf("[WrapKey] Tag is valid.\n"))
                ret_val := 0.U
                when(io.revoke || en_usage_ctr){
                    // midas.targetutils.SynthesizePrintf(printf("[WrapKey] Updating the HCB entry.\n"))
                    // Load the IV from Memory
                    io.maccess.address1 := io.addr2 + 16.U
                    io.maccess.address2 := io.addr2 + 24.U
                    io.maccess.load_store := 0.U
                    io.maccess.enable := "b11".U
                    cstate := CtrlState.sUpdateHandle
                }.otherwise{
                    cstate := CtrlState.sFinish
                }
            }.otherwise{
                midas.targetutils.SynthesizePrintf(printf("[WrapKey] Tag is invalid.\n"))
                ret_val := 1.U

                cstate := CtrlState.sFinish
            }            
        }
    }

    // -> sWaitForTag if revoke or usage counter
    when(cstate === CtrlState.sUpdateHandle && io.maccess.done){
        midas.targetutils.SynthesizePrintf(printf("[WrapKey] Usage ctr is %d.\n", usage_ctr))
        // Overwrite the HCB entry
        io.hcb.enable := true.B
        io.hcb.write := true.B
        io.hcb.iv := Cat(io.maccess.output2(31,0), io.maccess.output1)

        when(io.revoke  || usage_ctr === 1.U){
            io.hcb.dIN.valid := 0.U 
            io.hcb.dIN.ctr := 0.U
        }.otherwise{
            io.hcb.dIN.valid := 1.U 
            io.hcb.dIN.ctr := usage_ctr - 1.U
        }

        cstate := CtrlState.sFinish
    }

    when(cstate === CtrlState.sFinish && io.maccess.busy === false.B){
        // Reset AES GCM STATE
        io.aes.rst_i := true.B 
        io.aes.aes_gcm_pipe_reset_i := true.B
        // And we are done. 
        done := true.B
        cstate := CtrlState.sIdle
    }

    when(io.maccess.exception === true.B || io.hcb.xcpt === true.B){
        midas.targetutils.SynthesizePrintf(printf("[WrapKey] Exception occured.\n"))
        ret_val := 1.U
        cstate := CtrlState.sFinish
    }
}