# KeyVisor Hardware

The implementation of KeyVisor is based on the Chipyard framework and has been tested with [version 1.10](https://chipyard.readthedocs.io/en/1.10.0/).
To try KeyVisor for yourself, there are two options:

1. Use verilator to simulate a RocketChip CPU running in bare metal mode, or
2. Use Firesim to get KeyVisor running on an FPGA with a full Linux system and support for Keystone TEEs.

If you want to see how KeyVisor works and try it for yourself, option 1. is sufficient and is way easier.
If you want to see the use case examples in action or implement your own use cases, you will have to go for option 2.

## Verilator-based Simulation

KeyVisor is implemented as a RoCC accelerator, for general information refert to [the Chipyard documentation](https://chipyard.readthedocs.io/en/1.10.0/Customization/RoCC-Accelerators.html).
Setup and install Chipyard in version 1.10 according to the documentation. 
Make sure `env.sh` is sourced afterwards.

For the Verilator-based simulation, first copy the `keyvisor` folder to `chipyard/generators`.
Then add KeyVisor to the `build.sbt` file of Chipyard:
```
lazy val chipyard = ..., keyvisor,

lazy val keyvisor = (project in file("generators/keyvisor"))
  .dependsOn(rocketchip)
  .settings(libraryDependencies ++= rocketLibDeps.value)
  .settings(commonSettings)
```

Then, add a config file in `generators/chipyard/src/main/scala/config`:
```
package chipyard


import Chisel._
import freechips.rocketchip.rocket._
import freechips.rocketchip.diplomacy.{LazyModule,ValName}
import freechips.rocketchip.tile._
import org.chipsalliance.cde.config._

import keyvisor._

class KeyVisorConfig extends Config(
  new WithMyAESAccelerator ++
  new RocketConfig
  )

```

To run the simulation, refer to the software part of this repo to compile the bare metal demo program.
Then, go to `sims/verilator` and run `make -j32 run-binary VERILATOR_THREADS=28 LOADMEM=1 CONFIG=MKeyVisorConfig BINARY=[Path to Binary]`.
If you want debug output, i.e., traces, run `make -j32 run-binary-debug VERILATOR_THREADS=28 LOADMEM=1 CONFIG=MKeyVisorConfig BINARY=[Path to Binary]` instead.

The output should look something like this:
```
[UART] UART0 is here (stdin/stdout).
+ Started KeyVisor Demo
+ Creating Key Handle
+ Testing Encryption    1 / 1 Data Len: 4, AAD Len: 4
        + Encryption done; IV: bfe7476a 500fd5f7d47c2a10; 
                CT: c2 bb 2a 3d 
                GCM Auth Tag: bf 95 f6 2b 
        + Decryption done.
                PT: ff fe fd fc 
        + Test Successful, decrypted plaintext is correct and tags match.
+++ All tests finished successfully! +++
```

And that's it. You can now modify the demo program to run your own software with KeyVisor.


## Firesim-based Simulation

Setup FireSim as described in the [official documentation](https://docs.fires.im/en/stable/). 
We have tested KeyVisor with a Xilinx Alveo U250 card but it should work with any other supported FPGA as well.
You can also use Amazon Web Services to rent such an FPGA.
Note that the setup is not straightforward and we refer to the official FireSim documentation for this.

When  FireSim is working, you can simply create a config that loads the KeyVisor module in `chipyard/generators/firechip/src/main/scala/TargetConfigs.scala`:
```
import keyvisor._

... 

//*****************************************************************
// Rocket configs, base off chipyard's RocketConfig
//*****************************************************************

class FireSimKeyVisorConfig extends Config(
  new WithMyAESAccelerator ++
  new FireSimRocketConfig
)

class FireSimKeyVisorConfigNIC extends Config(
  new WithNIC ++
  new FireSimKeyVisorConfig
)


```

Go to `sims/firesim/deploy/config_build_recipes.yaml` and create a config, e.g.:
```
alveo_u250_firesim_rocket_singlecore_keyvisor_nic:
    PLATFORM: xilinx_alveo_u250
    TARGET_PROJECT: firesim
    DESIGN: FireSim
    TARGET_CONFIG: FireSimKeyVisorConfigNIC
    PLATFORM_CONFIG: BaseXilinxAlveoConfig
    deploy_quintuplet: null
    platform_config_args:
        fpga_frequency: 120
        build_strategy: TIMING
    post_build_hook: null
    metasim_customruntimeconfig: null
    bit_builder_recipe: bit-builder-recipes/xilinx_alveo_u250.yaml
```

Next, go to `sims/firesim/deploy/config_build.yaml` and make sure that the `builds_to_run` contains your new config. Set `default_build_dir` to any directory.

Then, go to `sims/firesim` and run
```
. sourceme-manager.sh --skip-ssh-setup
firesim buildbitstream 
```

If the authentication fails, run
```
sudo killall ssh-agent; eval "$(ssh-agent)"
ssh-add ~/.ssh/localhost 
```

Now wait, this is gonna take some time (still, check for errors from time to time. In my experience, it is fine as soon as vivado starts).  In the end you will get an output like this:
```
Your bitstream has been created!
Add

alveo_u250_firesim_rocket_singlecore_keyvisor_nic:
    bitstream_tar: file:///home/[USER]/chipyard/sims/firesim/deploy/results-build/2023-11-22--08-32-20-alveo_u250_firesim_rocket_singlecore_keyvisor_nic/cl_xilinx_alveo_u250-firesim-FireSim-FireSimKeyVisorConfigNIC-BaseXilinxAlveoConfig/firesim.tar.gz
    deploy_quintuplet_override: null
    custom_runtime_config: null

to your config_hwdb.yaml to use this hardware configuration.
```
Do that. Finally, set the `default_hw_config` in the `config_runtime.yaml` to the new target. If you have configured a NIC, make sure that `topology: example_1config` is set.

Then, run `firesim infrasetup`, setup the network adapter (if needed), and then run `firesim runworkload`.
You can connect to the console using `screen -r fsim0`


## Common Errors

If you get an error message like `undefined reference to \_\_libc_csu_fini`, you can fix it doing the following:
```
mv /home/USER/chipyard/.conda-env/bin/g++ /home/USER/chipyard/.conda-env/bin/g++_chipyard
ln -s /usr/bin/g++ /home/[USER]/chipyard/.conda-env/bin/g++
```
Note that you have to switch back to the original g++ when using Verilator instead of FireSim.


After a reboot, you probably have to rebuild/reload the drivers:
```
cd ~/dma_ip_drivers/XDMA/linux-kernel/xdma/
sudo make install
sudo insmod /lib/modules/$(uname -r)/extra/xdma.ko poll_mode=1

cd ~/dma_ip_drivers_xvsec/XVSEC/linux-kernel/
sudo make clean all
sudo make install
sudo modprobe xvsec
```


If you get an error during the QEMU build, you can try
```
cd keystone/qemu
./configure --target-list=riscv64-softmmu,riscv64-linux-user --disable-werror --cc=/usr/bin/cc --cxx=/usr/bin/cxx
make
```