For translation: 
```
yosys -m ghdl -p 'ghdl -fsynopsys gcm_pkg.vhd aes_pkg.vhd aes_func.vhd top_aes_gcm.vhd aes_gcm.vhd gcm_gctr.vhd aes_icb.vhd aes_round.vhd aes_last_round.vhd gcm_ghash.vhd ghash_gfmul.vhd aes_enc_dec_ctrl.vhd aes_kexp.vhd aes_ecb.vhd -e top_aes_gcm; write_verilog top_aes_gcm.v'; 
```
