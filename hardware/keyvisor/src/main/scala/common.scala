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
import scala.util.Random

object common {
    val rand     = new Random(2013)
    def generate_random_bigint() = BigInt(rand.nextLong()) + (BigInt(1) << 63)
  
    //def generate_random_bigint(size: Int) : BigInt = BigInt(rand.nextLong()) + (BigInt(1) << (size-1))
    def createBitmask(n: UInt): UInt = {
        val mask = Wire(Bits(width = 16))
        when(n < 16.U){
            mask := (1.U << n(3,0)) - 1.U
        }.otherwise{
            mask := "xFFFF".U
        }
        mask
    }

    def createBitmask2(n: UInt): UInt = {
        val mask = Wire(Bits(width = 64))
        when(n < 64.U){
            mask := (1.U << n(5,0)) - 1.U
        }.otherwise{
            mask := "xFFFFFFFFFFFFFFFF".U
        }
        mask
    }

    def swapEndiannes(in: UInt): UInt = {
        val rev = Wire(UInt(64.W))
        rev := Cat(in(7,0),in(15,8),in(23,16),in(31,24),in(39,32),in(47,40),in(55,48),in(63,56))
        rev
    }

    def swapBlocks4(in: UInt): UInt = {
        val ret = Wire(UInt(64.W))
        ret := Cat(in(31,0), in(63, 32))
        ret
    }

}
