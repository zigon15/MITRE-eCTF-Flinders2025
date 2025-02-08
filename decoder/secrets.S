.section .global_secrets
    .align 4

secrets_bin_start:
    .incbin "../design/output/secrets.bin"  // Include global secrets file
secrets_bin_end:

    .global secrets_bin_start
    .global secrets_bin_end