# KernelSU-Next (Fork)

This fork of KernelSU-Next is distinct from the original repository and includes specialized modifications for specific kernel environments.

## Key Differences

### CFI Bypass
This version includes a mechanism to bypass Control Flow Integrity (CFI), allowing for more flexible execution in restricted kernel environments.

### Dynamic Symbol Resolution & Patching
Unlike the original repository, which typically relies on exported symbols, this implementation **dynamically finds and patches kernel memory**. This allows it to work on kernels where standard symbol export mechanisms might be restricted or unavailable.

## Installation & Usage

Due to the nature of the dynamic patching and CFI bypass, this module **must** be loaded using `insmod`.

### Proper Loading Procedure

1.  **Build or Obtain the Module**: Ensure you have the compiled `kernelsu.ko` file.
2.  **Load with `insmod`**: Use the `insmod` command from a root shell or adb shell with root privileges.

    ```sh
    insmod /path/to/kernelsu.ko
    ```

    *Example:*
    ```sh
    adb shell su -c "insmod /data/local/tmp/kernelsu.ko"
    ```

**Important:** Standard loading methods or flashing zips designed for the upstream KernelSU may not work correctly with this fork due to the requirement for dynamic memory patching at the time of insertion.
