//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_execve")
int print_on_execve_call(){
    bpf_printk("syscall execve has been called");
}

SEC("tp/syscalls/sys_enter_open")
int print_on_file_open_call(){
    bpf_printk("syscall open has been called");
}


SEC("tp/syscalls/sys_enter_close")
int print_on_file_close_call(){
    bpf_printk("syscall close has been called");
}

char __license[] SEC("license") = "GPL";