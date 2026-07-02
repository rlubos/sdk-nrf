.. _crypto_x509_crt_stack_repro:

Crypto: Mbed TLS X.509 stack reproducer
#######################################

.. contents::
   :local:
   :depth: 2

This sample reproduces a fault that occurs when parsing an RSA X.509 certificate into a stack-allocated :c:struct:`mbedtls_x509_crt` object while NCS nRF Security is enabled.

The failure matches the one seen in the Zephyr ``net.tls_credentials.parse_crt`` test on Nordic Cortex-M targets such as ``nrf52840dk/nrf52840``.

Building and running
********************

.. include:: /includes/build_and_run.txt

.. code-block:: console

   west build -b nrf52840dk/nrf52840 nrf/samples/crypto/x509_crt_stack_repro
   west flash

Expected result on affected targets
===================================

The UART output shows successful parsing, then the device halts with a usage fault before ``Done`` is printed:

.. code-block:: console

   Parsing certificate with stack-allocated mbedtls_x509_crt
   Cert expires at 15/1/2038
   ***** USAGE FAULT *****
     Illegal use of the EPSR
   Faulting instruction address (r15/pc): 0x00000000
