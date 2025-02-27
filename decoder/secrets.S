.section .global_secrets
    .align 4

secrets_bin_start:
#ifdef DEV_BUILD
    #warning "Development Build!!"
    .incbin "../global.secrets"  // Include global secrets file
#else
    #warning "Production Build!!"
    .incbin "/global.secrets"  // Include global secrets file
#endif
secrets_bin_end:
    .global secrets_bin_start
    .global secrets_bin_end