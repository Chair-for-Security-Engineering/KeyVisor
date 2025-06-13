package keyvisor

import Chisel._
import chisel3.util.{HasBlackBoxResource,Reverse,UIntToOH}
import chisel3.{RawModule, withClockAndReset}
import chisel3.ChiselEnum
import freechips.rocketchip.tile._
import org.chipsalliance.cde.config._
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.rocket._
import chisel3.dontTouch

//import freechips.rocketchip.rocket.{TLBConfig, HellaCacheReq}

class WithMyAESAccelerator extends Config ((site, here, up) => {
  case BuildRoCC => up(BuildRoCC) ++ Seq(
    (p: Parameters) => {
      val aes = LazyModule.apply(new MyAESAccelerator(OpcodeSet.custom2)(p))
      aes
    }
  )
})


class MyAESAccelerator(opcodes: OpcodeSet)(implicit p: Parameters) extends LazyRoCC(opcodes, nPTWPorts = 1/*, roccCSRs = (new CustomCSRs).decls*/) {
  override lazy val module = new AESAcceleratorModule(this)
}

class WrapBundle(nPTWPorts: Int)(implicit p: Parameters) extends Bundle {
  val io = new RoCCIO(nPTWPorts,0)
  val clock = Clock(INPUT)
  val reset = Input(UInt(1.W))
}

//class MemAccessIO()(implicit val p: Parameters) extends Bundle with HasCoreParameters{
class AESCoreIO extends Bundle {
    val clk_i        = Input(Clock())
    val rst_i    = Input(Bool())
    val aes_gcm_mode_i = Input(Bits(2.W))
    val aes_gcm_enc_dec_i = Input(Bool())
    val aes_gcm_pipe_reset_i = Input(Bool())
    val aes_gcm_key_word_val_i = Input(Bits(4.W))
    val aes_gcm_key_word_i = Input(Bits(256.W))
    val aes_gcm_iv_val_i = Input(Bool())
    val aes_gcm_iv_i = Input(Bits(96.W))
    val aes_gcm_icb_start_cnt_i = Input(Bool())
    val aes_gcm_icb_stop_cnt_i = Input(Bool())
    val aes_gcm_ghash_pkt_val_i = Input(Bool())
    val aes_gcm_ghash_aad_bval_i = Input(Bits(16.W))
    val aes_gcm_ghash_aad_i  = Input(Bits(128.W))
    val aes_gcm_data_in_bval_i = Input(Bits(16.W))
    val aes_gcm_data_in_i = Input(Bits(128.W))
    val aes_gcm_ready_o  = Output(Bool())
    val aes_gcm_data_out_val_o = Output(Bool())
    val aes_gcm_data_out_bval_o  = Output(Bits(16.W))
    val aes_gcm_data_out_o  = Output(Bits(128.W))
    val aes_gcm_ghash_tag_val_o = Output(Bool())
    val aes_gcm_ghash_tag_o  = Output(Bits(128.W))
    val aes_gcm_icb_cnt_overflow_o = Output(Bool())
}

class top_aes_gcm(implicit p: Parameters) extends BlackBox with HasBlackBoxResource {
    val io = IO(new AESCoreIO)
    addResource("/ghdl/aes_128_s_vl_XS/top_aes_gcm.v")
}

class AESWrapper(implicit p: Parameters) extends Module{
    val io = IO(new AESCoreIO)

    val aesbb = Module(new top_aes_gcm)

    aesbb.io.aes_gcm_mode_i := io.aes_gcm_mode_i
    aesbb.io.aes_gcm_enc_dec_i := io.aes_gcm_enc_dec_i
    aesbb.io.aes_gcm_key_word_val_i := io.aes_gcm_key_word_val_i
    aesbb.io.aes_gcm_key_word_i := io.aes_gcm_key_word_i
    aesbb.io.aes_gcm_iv_val_i := io.aes_gcm_iv_val_i
    aesbb.io.aes_gcm_iv_i := io.aes_gcm_iv_i
    aesbb.io.aes_gcm_icb_start_cnt_i := io.aes_gcm_icb_start_cnt_i
    aesbb.io.aes_gcm_icb_stop_cnt_i := io.aes_gcm_icb_stop_cnt_i
    aesbb.io.aes_gcm_ghash_pkt_val_i := io.aes_gcm_ghash_pkt_val_i
    aesbb.io.aes_gcm_ghash_aad_bval_i := io.aes_gcm_ghash_aad_bval_i
    aesbb.io.aes_gcm_ghash_aad_i := io.aes_gcm_ghash_aad_i
    aesbb.io.aes_gcm_data_in_bval_i := io.aes_gcm_data_in_bval_i
    aesbb.io.aes_gcm_data_in_i := io.aes_gcm_data_in_i
    aesbb.io.clk_i := clock
    aesbb.io.rst_i := io.rst_i || reset.asBool()
    aesbb.io.aes_gcm_pipe_reset_i := io.aes_gcm_pipe_reset_i || reset.asBool()

    io.aes_gcm_ready_o := aesbb.io.aes_gcm_ready_o
    io.aes_gcm_data_out_val_o := aesbb.io.aes_gcm_data_out_val_o
    io.aes_gcm_data_out_bval_o  := aesbb.io.aes_gcm_data_out_bval_o
    io.aes_gcm_data_out_o  := aesbb.io.aes_gcm_data_out_o
    io.aes_gcm_ghash_tag_val_o := aesbb.io.aes_gcm_ghash_tag_val_o
    io.aes_gcm_ghash_tag_o  := aesbb.io.aes_gcm_ghash_tag_o
    io.aes_gcm_icb_cnt_overflow_o := aesbb.io.aes_gcm_icb_cnt_overflow_o
    //io <> aesbb.io // Does not work due to some chisel error
}

class AESAcceleratorModule(outer: MyAESAccelerator)(implicit p: Parameters)
    extends LazyRoCCModuleImp(outer) with HasCoreParameters {

    // Functions
    def loadKey128FromRegs(): Bits = {
        val key = Wire(Bits(width = 128))
        key := Cat(io.cmd.bits.rs1, io.cmd.bits.rs2)
        key
    }

    // Statemachine
    object CtrlState extends ChiselEnum {
        val sIdle, sHandleWrap, sEncDec, sFinish = Value
    }
    val cstate = RegInit(CtrlState.sIdle)

    private val ptw = io.ptw(0)
    //val satp = Mux(io.cmd.bits.status.dprv =/= 0.U, ptw.vsatp, ptw.ptbr)
    val satp = /*Mux(io.cmd.bits.status.dprv =/= 0.U, ptw.vsatp, */ptw.ptbr//)
    // Modules
    val handle_wrapper = Module(new HandleWrapper)
    val enc_dec_unit = Module(new EncDecUnit)
    val aesbb = Module(new AESWrapper)
    val maccess = Module(new MemAccess)
    val gen_iv = Module(new IVGen)
    val hcb = Module(new HandleCache)

    // KeyVisor Registers
    val keyValid = RegInit(Bool(false))
    val CPUKey = Reg(Bits(width = 128))
    val out_buf = Reg(Bits(width = 64))
    val rs1_buf = Reg(Bits(width = coreMaxAddrBits))
    val rs2_buf = Reg(Bits(width = coreMaxAddrBits))

//val csr = dontTouch(Wire(io.csrs))
    // val timeout = Reg(UInt(64.W))
    // ROCC Status
    val req_rd = Reg(Bits(width = 5))
    val funct = io.cmd.bits.inst.funct
    val loadKey = funct === UInt(0)
    val wrapKey = funct === UInt(1)
    val doENC = funct === UInt(2)
    val doDEC = funct === UInt(3)
    val revoke = funct === UInt(4)
    object TASK extends ChiselEnum {
        val loadKey, wrapKey, doENC, doDEC, revokeHandle = Value
    }
    val task = RegInit(TASK.loadKey)


    // Wire the Memory Access Module
    when(cstate === CtrlState.sHandleWrap){
        handle_wrapper.io.maccess <> maccess.io.ports
    }.otherwise{
        enc_dec_unit.io.maccess <> maccess.io.ports
    }
    io.mem <> maccess.io.mem
    when(io.exception === true.B){
        printf("ROCC Exception\n");
    }

    // Wire the SRAM Module
    handle_wrapper.io.hcb <> hcb.io
    
    // Wire the HandleEnc Module
    handle_wrapper.io.enable := false.B
    handle_wrapper.io.encdec := false.B
    handle_wrapper.io.addr1  := rs1_buf(coreMaxAddrBits-1, 0)
    handle_wrapper.io.addr2 := rs2_buf(coreMaxAddrBits-1, 0)
    handle_wrapper.io.keyValid := keyValid
    handle_wrapper.io.CPUKey := CPUKey
    handle_wrapper.io.dprv :=  io.cmd.bits.status.dprv
    handle_wrapper.io.dv := io.cmd.bits.status.dv
    handle_wrapper.io.revoke := task === TASK.revokeHandle
    handle_wrapper.io.satp := Cat(satp.mode, satp.asid, satp.ppn)

    handle_wrapper.io.pmp.addr(0) := ptw.pmp(0).addr
    handle_wrapper.io.pmp.addr(1) := ptw.pmp(1).addr
    handle_wrapper.io.pmp.addr(2) := ptw.pmp(2).addr
    handle_wrapper.io.pmp.addr(3) := ptw.pmp(3).addr
    handle_wrapper.io.pmp.addr(4) := ptw.pmp(4).addr
    handle_wrapper.io.pmp.addr(5) := ptw.pmp(5).addr
    handle_wrapper.io.pmp.addr(6) := ptw.pmp(6).addr
    handle_wrapper.io.pmp.addr(7) := ptw.pmp(7).addr

    handle_wrapper.io.pmp.r(0) := ptw.pmp(0).cfg.r
    handle_wrapper.io.pmp.r(1) := ptw.pmp(1).cfg.r
    handle_wrapper.io.pmp.r(2) := ptw.pmp(2).cfg.r
    handle_wrapper.io.pmp.r(3) := ptw.pmp(3).cfg.r
    handle_wrapper.io.pmp.r(4) := ptw.pmp(4).cfg.r
    handle_wrapper.io.pmp.r(5) := ptw.pmp(5).cfg.r
    handle_wrapper.io.pmp.r(6) := ptw.pmp(6).cfg.r
    handle_wrapper.io.pmp.r(7) := ptw.pmp(7).cfg.r

    handle_wrapper.io.pmp.w(0) := ptw.pmp(0).cfg.w
    handle_wrapper.io.pmp.w(1) := ptw.pmp(1).cfg.w
    handle_wrapper.io.pmp.w(2) := ptw.pmp(2).cfg.w
    handle_wrapper.io.pmp.w(3) := ptw.pmp(3).cfg.w
    handle_wrapper.io.pmp.w(4) := ptw.pmp(4).cfg.w
    handle_wrapper.io.pmp.w(5) := ptw.pmp(5).cfg.w
    handle_wrapper.io.pmp.w(6) := ptw.pmp(6).cfg.w
    handle_wrapper.io.pmp.w(7) := ptw.pmp(7).cfg.w

    handle_wrapper.io.pmp.x(0) := ptw.pmp(0).cfg.x
    handle_wrapper.io.pmp.x(1) := ptw.pmp(1).cfg.x
    handle_wrapper.io.pmp.x(2) := ptw.pmp(2).cfg.x
    handle_wrapper.io.pmp.x(3) := ptw.pmp(3).cfg.x
    handle_wrapper.io.pmp.x(4) := ptw.pmp(4).cfg.x
    handle_wrapper.io.pmp.x(5) := ptw.pmp(5).cfg.x
    handle_wrapper.io.pmp.x(6) := ptw.pmp(6).cfg.x
    handle_wrapper.io.pmp.x(7) := ptw.pmp(7).cfg.x

    // Wire the EncDec Module
    enc_dec_unit.io.enable := false.B
    enc_dec_unit.io.addr1  := rs1_buf(coreMaxAddrBits-1, 0)
    enc_dec_unit.io.addr2 := rs2_buf(coreMaxAddrBits-1, 0)
    enc_dec_unit.io.dprv :=  io.cmd.bits.status.dprv
    enc_dec_unit.io.dv := io.cmd.bits.status.dv
    enc_dec_unit.io.wrappedKey := handle_wrapper.io.wrappedKey
    enc_dec_unit.io.encdec := false.B
    // enc_dec_unit.reset := false.B

    // Wire the AES Module
    handle_wrapper.io.aes.aes_gcm_ready_o := aesbb.io.aes_gcm_ready_o
    handle_wrapper.io.aes.aes_gcm_data_out_val_o := aesbb.io.aes_gcm_data_out_val_o
    handle_wrapper.io.aes.aes_gcm_data_out_bval_o  := aesbb.io.aes_gcm_data_out_bval_o
    handle_wrapper.io.aes.aes_gcm_data_out_o  := aesbb.io.aes_gcm_data_out_o
    handle_wrapper.io.aes.aes_gcm_ghash_tag_val_o := aesbb.io.aes_gcm_ghash_tag_val_o
    handle_wrapper.io.aes.aes_gcm_ghash_tag_o  := aesbb.io.aes_gcm_ghash_tag_o
    handle_wrapper.io.aes.aes_gcm_icb_cnt_overflow_o := aesbb.io.aes_gcm_icb_cnt_overflow_o
    enc_dec_unit.io.aes.aes_gcm_ready_o := aesbb.io.aes_gcm_ready_o
    enc_dec_unit.io.aes.aes_gcm_data_out_val_o := aesbb.io.aes_gcm_data_out_val_o
    enc_dec_unit.io.aes.aes_gcm_data_out_bval_o  := aesbb.io.aes_gcm_data_out_bval_o
    enc_dec_unit.io.aes.aes_gcm_data_out_o  := aesbb.io.aes_gcm_data_out_o
    enc_dec_unit.io.aes.aes_gcm_ghash_tag_val_o := aesbb.io.aes_gcm_ghash_tag_val_o
    enc_dec_unit.io.aes.aes_gcm_ghash_tag_o  := aesbb.io.aes_gcm_ghash_tag_o
    enc_dec_unit.io.aes.aes_gcm_icb_cnt_overflow_o := aesbb.io.aes_gcm_icb_cnt_overflow_o
    when(cstate === CtrlState.sHandleWrap){
        aesbb.io.aes_gcm_mode_i := handle_wrapper.io.aes.aes_gcm_mode_i
        aesbb.io.aes_gcm_enc_dec_i := handle_wrapper.io.aes.aes_gcm_enc_dec_i
        aesbb.io.aes_gcm_pipe_reset_i := handle_wrapper.io.aes.aes_gcm_pipe_reset_i
        aesbb.io.rst_i := handle_wrapper.io.aes.rst_i
        aesbb.io.aes_gcm_key_word_val_i := handle_wrapper.io.aes.aes_gcm_key_word_val_i
        aesbb.io.aes_gcm_key_word_i := handle_wrapper.io.aes.aes_gcm_key_word_i
        aesbb.io.aes_gcm_iv_val_i := handle_wrapper.io.aes.aes_gcm_iv_val_i
        aesbb.io.aes_gcm_iv_i := handle_wrapper.io.aes.aes_gcm_iv_i
        aesbb.io.aes_gcm_icb_start_cnt_i := handle_wrapper.io.aes.aes_gcm_icb_start_cnt_i
        aesbb.io.aes_gcm_icb_stop_cnt_i := handle_wrapper.io.aes.aes_gcm_icb_stop_cnt_i
        aesbb.io.aes_gcm_ghash_pkt_val_i := handle_wrapper.io.aes.aes_gcm_ghash_pkt_val_i
        aesbb.io.aes_gcm_ghash_aad_bval_i := handle_wrapper.io.aes.aes_gcm_ghash_aad_bval_i
        aesbb.io.aes_gcm_ghash_aad_i := handle_wrapper.io.aes.aes_gcm_ghash_aad_i
        aesbb.io.aes_gcm_data_in_bval_i := handle_wrapper.io.aes.aes_gcm_data_in_bval_i
        aesbb.io.aes_gcm_data_in_i := handle_wrapper.io.aes.aes_gcm_data_in_i
        //handle_wrapper.io.aes <> aesbb.io // Does not work due to FIRTTL Error
    }.otherwise{
        aesbb.io.aes_gcm_mode_i := enc_dec_unit.io.aes.aes_gcm_mode_i
        aesbb.io.aes_gcm_enc_dec_i := enc_dec_unit.io.aes.aes_gcm_enc_dec_i
        aesbb.io.aes_gcm_pipe_reset_i := enc_dec_unit.io.aes.aes_gcm_pipe_reset_i
        aesbb.io.rst_i := enc_dec_unit.io.aes.rst_i
        aesbb.io.aes_gcm_key_word_val_i := enc_dec_unit.io.aes.aes_gcm_key_word_val_i
        aesbb.io.aes_gcm_key_word_i := enc_dec_unit.io.aes.aes_gcm_key_word_i
        aesbb.io.aes_gcm_iv_val_i := enc_dec_unit.io.aes.aes_gcm_iv_val_i
        aesbb.io.aes_gcm_iv_i := enc_dec_unit.io.aes.aes_gcm_iv_i
        aesbb.io.aes_gcm_icb_start_cnt_i := enc_dec_unit.io.aes.aes_gcm_icb_start_cnt_i
        aesbb.io.aes_gcm_icb_stop_cnt_i := enc_dec_unit.io.aes.aes_gcm_icb_stop_cnt_i
        aesbb.io.aes_gcm_ghash_pkt_val_i := enc_dec_unit.io.aes.aes_gcm_ghash_pkt_val_i
        aesbb.io.aes_gcm_ghash_aad_bval_i := enc_dec_unit.io.aes.aes_gcm_ghash_aad_bval_i
        aesbb.io.aes_gcm_ghash_aad_i := enc_dec_unit.io.aes.aes_gcm_ghash_aad_i
        aesbb.io.aes_gcm_data_in_bval_i := enc_dec_unit.io.aes.aes_gcm_data_in_bval_i
        aesbb.io.aes_gcm_data_in_i := enc_dec_unit.io.aes.aes_gcm_data_in_i
        //enc_dec_unit.io.aes <> aesbb.io // Does not work due to FIRTTL Error
    }
    // aesbb.reset := false.B

    // Wire the GenIV Module
    when(cstate === CtrlState.sHandleWrap){
        handle_wrapper.io.genIV <> gen_iv.io
    }.otherwise{
        enc_dec_unit.io.genIV <> gen_iv.io
    }
    // gen_iv.reset := false.B

    // Default Signal Assign:
    io.cmd.ready := (cstate === CtrlState.sIdle)
    io.busy := (cstate =/= CtrlState.sIdle)
    io.resp.valid := false.B
    io.resp.bits.rd := req_rd

    // when(cstate =/= CtrlState.sIdle && io.cmd.fire){
    //     midas.targetutils.SynthesizePrintf(printf("[KeyVisor] Instruction fired while busy!\n"))
    // }
    
    // Printf debugging with hanging simulator
    //  when(cstate =/= CtrlState.sIdle){
        //when(timeout === "h5d21dba00".U){
            // midas.targetutils.SynthesizePrintf(printf(".\n"))
        //    midas.targetutils.
        //    timeout := 0.U
        //}.otherwise{
        //    timeout := timeout + 1.U
        //}
    //  }

    when(cstate === CtrlState.sIdle && io.cmd.fire) { // Instruction is executing
        // timeout := 0.U
        midas.targetutils.SynthesizePrintf(printf("[KeyVisor] Instruction fired and state was idle\n"))
        midas.targetutils.SynthesizePrintf(printf("[KeyVisor] VSATP: %x, PTBR: %x\n", Cat(ptw.vsatp.mode, ptw.vsatp.asid, ptw.vsatp.ppn), Cat(ptw.ptbr.mode, ptw.ptbr.asid, ptw.ptbr.ppn)))
        
        midas.targetutils.SynthesizePrintf(printf("""[KeyVisor] PMP Modes:
            PMP0: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x 
            PMP1: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x
            PMP2: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x
            PMP3: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x
            PMP4: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x
            PMP5: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x
            PMP6: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x
            PMP7: CFG L: %d, R %d, W %d, X %d, A: %d, Addr: %x
        """
        , ptw.pmp(0).cfg.l, ptw.pmp(0).cfg.r, ptw.pmp(0).cfg.w, ptw.pmp(0).cfg.x, ptw.pmp(0).cfg.a, ptw.pmp(0).addr
        , ptw.pmp(1).cfg.l, ptw.pmp(1).cfg.r, ptw.pmp(1).cfg.w, ptw.pmp(1).cfg.x, ptw.pmp(1).cfg.a, ptw.pmp(1).addr
        , ptw.pmp(2).cfg.l, ptw.pmp(2).cfg.r, ptw.pmp(2).cfg.w, ptw.pmp(2).cfg.x, ptw.pmp(2).cfg.a, ptw.pmp(2).addr
        , ptw.pmp(3).cfg.l, ptw.pmp(3).cfg.r, ptw.pmp(3).cfg.w, ptw.pmp(3).cfg.x, ptw.pmp(3).cfg.a, ptw.pmp(3).addr
        , ptw.pmp(4).cfg.l, ptw.pmp(4).cfg.r, ptw.pmp(4).cfg.w, ptw.pmp(4).cfg.x, ptw.pmp(4).cfg.a, ptw.pmp(4).addr
        , ptw.pmp(5).cfg.l, ptw.pmp(5).cfg.r, ptw.pmp(5).cfg.w, ptw.pmp(5).cfg.x, ptw.pmp(5).cfg.a, ptw.pmp(5).addr
        , ptw.pmp(6).cfg.l, ptw.pmp(6).cfg.r, ptw.pmp(6).cfg.w, ptw.pmp(6).cfg.x, ptw.pmp(6).cfg.a, ptw.pmp(6).addr
        , ptw.pmp(7).cfg.l, ptw.pmp(7).cfg.r, ptw.pmp(7).cfg.w, ptw.pmp(7).cfg.x, ptw.pmp(7).cfg.a, ptw.pmp(7).addr
        ))

        
        req_rd := io.cmd.bits.inst.rd
        rs1_buf := io.cmd.bits.rs1
        rs2_buf := io.cmd.bits.rs2
        // cstate := CtrlState.sFinish

        when(loadKey){
            task := TASK.loadKey
            CPUKey := loadKey128FromRegs()
            keyValid := true.B
            //midas.targetutils.SynthesizePrintf(printf("[AES] LOAD CPU KEY: %x\n", loadKey128FromRegs()))
            when(keyValid === true.B){
                out_buf := 2.U
            }otherwise{
                out_buf := 0.U
            }
            cstate := CtrlState.sFinish
        }
        when(wrapKey){
            task := TASK.wrapKey
            handle_wrapper.io.enable := true.B
            handle_wrapper.io.encdec := false.B

            cstate := CtrlState.sHandleWrap
        }
        when(doENC){
            task := TASK.doENC
            handle_wrapper.io.enable := true.B
            handle_wrapper.io.encdec := true.B

            cstate := CtrlState.sHandleWrap
        }
        when(doDEC){
            task := TASK.doDEC
            handle_wrapper.io.enable := true.B
            handle_wrapper.io.encdec := true.B

            cstate := CtrlState.sHandleWrap
        }
        when(revoke){
            task := TASK.revokeHandle
            handle_wrapper.io.enable := true.B
            handle_wrapper.io.encdec := true.B
            cstate := CtrlState.sHandleWrap
        }
    }

 
    when(cstate === CtrlState.sHandleWrap){
        when(handle_wrapper.io.done === true.B){
            out_buf := handle_wrapper.io.retVal
            when(task === TASK.wrapKey || task === TASK.revokeHandle || handle_wrapper.io.retVal =/= 0.U){
                cstate := CtrlState.sFinish
            }.elsewhen(task === TASK.doENC ){
                // printf(midas.targetutils.SynthesizePrintf("Staring ENC at TS: %d\n", timeout))
                when(handle_wrapper.io.allow_enc === false.B){
                    out_buf := 2.U
                    cstate := CtrlState.sFinish
                }.otherwise{
                    enc_dec_unit.io.enable := true.B
                    cstate := CtrlState.sEncDec
                }
            }.elsewhen(task === TASK.doDEC){
                // printf(midas.targetutils.SynthesizePrintf("Staring DEC at TS: %d\n", timeout))
                when(handle_wrapper.io.allow_dec === false.B){
                    out_buf := 2.U
                    cstate := CtrlState.sFinish
                }.otherwise{
                    enc_dec_unit.io.enable := true.B
                    cstate := CtrlState.sEncDec
                }
            }
        }
    }

    when(cstate === CtrlState.sEncDec){
        when(task === TASK.doENC){
            enc_dec_unit.io.encdec := false.B
        }.otherwise{
            enc_dec_unit.io.encdec := true.B
        }

        when(enc_dec_unit.io.done === true.B){
            out_buf := enc_dec_unit.io.retVal
            cstate := CtrlState.sFinish
        }
    }

    when(cstate === CtrlState.sFinish && maccess.io.ports.busy === false.B){
        midas.targetutils.SynthesizePrintf(printf("[KeyVisor] Instruction finished with return value %d\n", out_buf))
        io.resp.valid := true.B
        io.resp.bits.data := out_buf
        cstate := CtrlState.sIdle
    }

    // Exception handling
    when(maccess.io.ports.exception === true.B){
        out_buf:= 1.U
        cstate := CtrlState.sFinish
    }
    
    io.interrupt := Bool(false)

}