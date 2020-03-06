Return-Path: <kasan-dev+bncBDK3TPOVRULBB2FGQ3ZQKGQEQDOTJYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D8DCC17B29E
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 01:03:52 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id p4sf3279563wmp.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 16:03:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583453032; cv=pass;
        d=google.com; s=arc-20160816;
        b=lrTyx65C6EjqGtIm+KhSmo1Kxq7WNuEf04pva3hSJDvxUPCtcXwIllqn+Zom4KRLHL
         QMrSj1J3StJwdqIVHqDmYb/0VgWbmvxESv1ofFi/Mj30J+lFCLg4cgKiCJYcbcER7XwS
         Tl7zLWdNay1vytF/UpzGVIjVWSTvWOM00Cs9nbbnCDg6mMQSuZuZ/7QN7aB/Uq5isDNA
         VnOnT5sN36sCXQscEaa9sqCuqOor/BGIUHFOfxmjtDwMfJXRE1rQQWIsw+LtWZRzHgBB
         K9A8q9nA5w41SpHWM27vlxwNQ2Cq3Kcrlucb5cRSYsWuGZvyU/0RCbGzBcIT4fzIjY8p
         WUzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5Ier693SZMPyq3f85fHcj57K6S1tFfBLkf6ocdnNDGE=;
        b=xk4nMugxtdS+1E2qL/GsClysCq/IdwLLIbAcTMWJBP19P7CAO8j9WG1WUkBSaVDjdE
         dpnYfa7Kx2ocPJvHiLusIwELNJMpcYiwDul/KRQpRLOzhHYQ49mdSLV9h7B2/z++4FmD
         ZmADWTp99akou4YdMmruhvuGoslcYdzdsIGFgrInfGabXqANYbQj3L1YWpLOYsnHlAWP
         sUU9U85WHOkeRr6aDsJ57A33HWAXrAFJIQ9P5zwcUz9au1R+G1M+E18MfLR/ERwL0wv+
         AEmOdewfvmuXvHFLgGJKDl9D9jURmTxqWtwmaTJq/mWxB3vRJ2/8cxFdYoWyKD+aK72Z
         s10A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VuT04Zcx;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Ier693SZMPyq3f85fHcj57K6S1tFfBLkf6ocdnNDGE=;
        b=gHegZUzHRP38uEPIlslIdjZVV+HwA9lVsb+/u16GQA5dGHdFkKia5CkOb8Y2RRYfmq
         1qjfunwvz4cDFgWRrbOD8YA1X0Mo962hz91dZdjjfSEl6HgFzjMF8hfxZH+oRszkybsE
         fUQ9Rjv7Y0c+5WRGKSIqRRQlpJ6dBBBwNmseR0LBB1gRYKtHfiN/iKPmTfsWCIva16L3
         ka4XAPhenP5RoHZ0AdhQcbkgbTtKpIANiftJ1tjyCO/KWRkvUXYEyTxfhI6EDWbbR6OO
         96ai6+1nhxmZRP36Efi7IKl2peF9s1/2siqApRHXxC6mpt+AM7JVLINFuN928IorVO6M
         O7rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Ier693SZMPyq3f85fHcj57K6S1tFfBLkf6ocdnNDGE=;
        b=hAZX2siy9qLxibf2YEe9S/6egBFmi2DJeRrnZ2HZLdQXzcXmeyCzlDvOwkVBIA3wdS
         q6w+3vV5eXZYLbWh+FgLWezbBfSm2DUre/IDPBiOAQbwbIbvvIiVuYEyT1SGmLkv/Ro6
         aIsUgOPUMuZsGcRKlO7QZJPElTi7/OyHmKop5YaLO+QpV28xrYf8PbpyKi70DYMoJTMg
         8hdG2+2OYb8eds4iVPiVd1P4GwrFTzX4vFZtMXU/2vPMf3l6bHYFmQpUv8O0034F+rVh
         gclVQl458dA/MOPaYVz/nIBAWnItMB4YgUmoC4c6rT8F7T64uTQSYMQSRF8qPG0OhyCo
         1lPQ==
X-Gm-Message-State: ANhLgQ2pjI4JGlX5i2b8d96fc+T2SUcC7hAOs4/UBNpzQnBU6uUJYqez
	41yP1uL8L9fA2HPpmzDAVAU=
X-Google-Smtp-Source: ADFU+vvKELOzeYmuDXoqgGrfsNHrA5yaVnEzB2p9fafJwciGvZsgR3uiWKgBDjMT67MdtnbLwZzRoQ==
X-Received: by 2002:adf:ee86:: with SMTP id b6mr438769wro.282.1583453032563;
        Thu, 05 Mar 2020 16:03:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f091:: with SMTP id n17ls309939wro.8.gmail; Thu, 05 Mar
 2020 16:03:52 -0800 (PST)
X-Received: by 2002:a5d:6b8d:: with SMTP id n13mr483121wrx.292.1583453031995;
        Thu, 05 Mar 2020 16:03:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583453031; cv=none;
        d=google.com; s=arc-20160816;
        b=ZR4FtiTwBYtskk9UVLzJwVf55pr95ATho1lly8KWQH1tL5eFTruC8v2+XhcXtL7Gjh
         /j9Vnzh5welz07S45Mau0qP6FoiBQZnjfl8Q3eME63Wsf8obXPmDXAG4jqCofAeFh8o2
         wbLJuIYYKdUgLGbjYHgPd5N6rMP+58VrQZalDHAVKUFQsGEh0Q0Svdn7GS20lxcSHDEu
         kx+2ZkoDhxUCTY8GD8+OxL07xy+Ziz3/zakEkbMvfGlLQIUOD26ZV4KTJZOooVJ/prhG
         sBnZOi92325tW5I+rHTSoJURKgOUYpI5Cci9oXiD0CB8QBtTME051wPHa9T9J+buhuwr
         yXaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UgANqYbsGGPlfxgnPY19cqvlngm9uRL0rxGTl9wSa3M=;
        b=UaLiSRLKChjc6DNG8PmruLBehuedRTzuMK6OSXhKDfvyW/GrXRDBA9iVYSzgNvA2oI
         XRvGSroulhYB4sOqyKQGofrwZ/pAfW1fSAeCjLVoQaI15pv+KrQ/W9RMvfs+xivPtwk1
         3rXd3zneimStE9PYki57uTcsSGWboaAvYyzpCKUAq19iUjJ9sN0Q2d8iihrfSMEQ2O2C
         xBuy0MRQnyrv2xP1RY3weYEfLOTE1qFqPWKKzZUPuodte7quda+hiE8OfbBylYq2COu7
         WXFM04d84SXngcBR2PkbBjk7KBtYlwMAQ6JzbnP2KWHu2VXRh2IcG0NgnqGweV/bux4v
         kfEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VuT04Zcx;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id d14si18558wru.1.2020.03.05.16.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 16:03:51 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id v2so245146wrp.12
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 16:03:51 -0800 (PST)
X-Received: by 2002:adf:e38d:: with SMTP id e13mr416724wrm.133.1583453031144;
 Thu, 05 Mar 2020 16:03:51 -0800 (PST)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
In-Reply-To: <20200226004608.8128-1-trishalfonso@google.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 16:03:39 -0800
Message-ID: <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>, 
	Johannes Berg <johannes@sipsolutions.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VuT04Zcx;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Tue, Feb 25, 2020 at 4:46 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> Make KASAN run on User Mode Linux on x86_64.
>
> Depends on Constructor support in UML - "[RFC PATCH] um:
> implement CONFIG_CONSTRUCTORS for modules"
> (https://patchwork.ozlabs.org/patch/1234551/) by Johannes Berg.
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the
> KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
> space, and KASAN requires 1/8th of this. The default location of
> this offset is 0x7fff8000 as suggested by Dmitry Vyukov. There is
> usually enough free space at this location; however, it is a config
> option so that it can be easily changed if needed.
>
> The UML-specific KASAN initializer uses mmap to map
> the roughly 2.25TB of shadow memory to the location defined by
> KASAN_SHADOW_OFFSET. kasan_init() utilizes constructors to initialize
> KASAN before main().
>
> Disable stack instrumentation on UML via KASAN_STACK config option to
> avoid false positive KASAN reports.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---

Hi all, I just want to bump this so we can get all the comments while
this is still fresh in everyone's minds. I would love if some UML
maintainers could give their thoughts!

Thanks,
Patricia

>  arch/um/Kconfig                  | 13 +++++++++++++
>  arch/um/Makefile                 |  6 ++++++
>  arch/um/include/asm/common.lds.S |  1 +
>  arch/um/include/asm/kasan.h      | 32 ++++++++++++++++++++++++++++++++
>  arch/um/kernel/dyn.lds.S         |  5 ++++-
>  arch/um/kernel/mem.c             | 18 ++++++++++++++++++
>  arch/um/os-Linux/mem.c           | 22 ++++++++++++++++++++++
>  arch/um/os-Linux/user_syms.c     |  4 ++--
>  arch/x86/um/Makefile             |  3 ++-
>  arch/x86/um/vdso/Makefile        |  3 +++
>  lib/Kconfig.kasan                |  2 +-
>  11 files changed, 104 insertions(+), 5 deletions(-)
>  create mode 100644 arch/um/include/asm/kasan.h
>
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 0917f8443c28..fb2ad1fb05fd 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -8,6 +8,7 @@ config UML
>         select ARCH_HAS_KCOV
>         select ARCH_NO_PREEMPT
>         select HAVE_ARCH_AUDITSYSCALL
> +       select HAVE_ARCH_KASAN if X86_64
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ASM_MODVERSIONS
>         select HAVE_UID16
> @@ -200,6 +201,18 @@ config UML_TIME_TRAVEL_SUPPORT
>
>           It is safe to say Y, but you probably don't need this.
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x7fff8000
> +       help
> +         This is the offset at which the ~2.25TB of shadow memory is
> +         mapped and used by KASAN for memory debugging. This can be any
> +         address that has at least KASAN_SHADOW_SIZE(total address space divided
> +         by 8) amount of space so that the KASAN shadow memory does not conflict
> +         with anything. The default is 0x7fff8000, as it fits into immediate of
> +         most instructions.
> +
>  endmenu
>
>  source "arch/um/drivers/Kconfig"
> diff --git a/arch/um/Makefile b/arch/um/Makefile
> index d2daa206872d..28fe7a9a1858 100644
> --- a/arch/um/Makefile
> +++ b/arch/um/Makefile
> @@ -75,6 +75,12 @@ USER_CFLAGS = $(patsubst $(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
>                 -D_FILE_OFFSET_BITS=64 -idirafter $(srctree)/include \
>                 -idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__
>
> +# Kernel config options are not included in USER_CFLAGS, but the option for KASAN
> +# should be included if the KASAN config option was set.
> +ifdef CONFIG_KASAN
> +       USER_CFLAGS+=-DCONFIG_KASAN=y
> +endif
> +
>  #This will adjust *FLAGS accordingly to the platform.
>  include $(ARCH_DIR)/Makefile-os-$(OS)
>
> diff --git a/arch/um/include/asm/common.lds.S b/arch/um/include/asm/common.lds.S
> index eca6c452a41b..731f8c8422a2 100644
> --- a/arch/um/include/asm/common.lds.S
> +++ b/arch/um/include/asm/common.lds.S
> @@ -83,6 +83,7 @@
>    }
>    .init_array : {
>         __init_array_start = .;
> +       *(.kasan_init)
>         *(.init_array)
>         __init_array_end = .;
>    }
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> new file mode 100644
> index 000000000000..2b81e7bcd4af
> --- /dev/null
> +++ b/arch/um/include/asm/kasan.h
> @@ -0,0 +1,32 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_UM_KASAN_H
> +#define __ASM_UM_KASAN_H
> +
> +#include <linux/init.h>
> +#include <linux/const.h>
> +
> +#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +
> +/* used in kasan_mem_to_shadow to divide by 8 */
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +
> +#ifdef CONFIG_X86_64
> +#define KASAN_HOST_USER_SPACE_END_ADDR 0x00007fffffffffffUL
> +/* KASAN_SHADOW_SIZE is the size of total address space divided by 8 */
> +#define KASAN_SHADOW_SIZE ((KASAN_HOST_USER_SPACE_END_ADDR + 1) >> \
> +                       KASAN_SHADOW_SCALE_SHIFT)
> +#else
> +#error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
> +#endif /* CONFIG_X86_64 */
> +
> +#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
> +#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> +
> +#ifdef CONFIG_KASAN
> +void kasan_init(void);
> +void kasan_map_memory(void *start, unsigned long len);
> +#else
> +static inline void kasan_init(void) { }
> +#endif /* CONFIG_KASAN */
> +
> +#endif /* __ASM_UM_KASAN_H */
> diff --git a/arch/um/kernel/dyn.lds.S b/arch/um/kernel/dyn.lds.S
> index f5001481010c..d91bdb2c3143 100644
> --- a/arch/um/kernel/dyn.lds.S
> +++ b/arch/um/kernel/dyn.lds.S
> @@ -103,7 +103,10 @@ SECTIONS
>       be empty, which isn't pretty.  */
>    . = ALIGN(32 / 8);
>    .preinit_array     : { *(.preinit_array) }
> -  .init_array     : { *(.init_array) }
> +  .init_array     : {
> +    *(.kasan_init)
> +    *(.init_array)
> +  }
>    .fini_array     : { *(.fini_array) }
>    .data           : {
>      INIT_TASK_DATA(KERNEL_STACK_SIZE)
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 30885d0b94ac..7b0d028aa079 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -18,6 +18,24 @@
>  #include <kern_util.h>
>  #include <mem_user.h>
>  #include <os.h>
> +#include <linux/sched/task.h>
> +
> +#ifdef CONFIG_KASAN
> +void kasan_init(void)
> +{
> +       /*
> +        * kasan_map_memory will map all of the required address space and
> +        * the host machine will allocate physical memory as necessary.
> +        */
> +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +       init_task.kasan_depth = 0;
> +       os_info("KernelAddressSanitizer initialized\n");
> +}
> +
> +static void (*kasan_init_ptr)(void)
> +__section(.kasan_init) __used
> += kasan_init;
> +#endif
>
>  /* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
>  unsigned long *empty_zero_page = NULL;
> diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
> index 3c1b77474d2d..8530b2e08604 100644
> --- a/arch/um/os-Linux/mem.c
> +++ b/arch/um/os-Linux/mem.c
> @@ -17,6 +17,28 @@
>  #include <init.h>
>  #include <os.h>
>
> +/*
> + * kasan_map_memory - maps memory from @start with a size of @len.
> + * The allocated memory is filled with zeroes upon success.
> + * @start: the start address of the memory to be mapped
> + * @len: the length of the memory to be mapped
> + *
> + * This function is used to map shadow memory for KASAN in uml
> + */
> +void kasan_map_memory(void *start, size_t len)
> +{
> +       if (mmap(start,
> +                len,
> +                PROT_READ|PROT_WRITE,
> +                MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
> +                -1,
> +                0) == MAP_FAILED) {
> +               os_info("Couldn't allocate shadow memory: %s\n.",
> +                       strerror(errno));
> +               exit(1);
> +       }
> +}
> +
>  /* Set by make_tempfile() during early boot. */
>  static char *tempdir = NULL;
>
> diff --git a/arch/um/os-Linux/user_syms.c b/arch/um/os-Linux/user_syms.c
> index 715594fe5719..cb667c9225ab 100644
> --- a/arch/um/os-Linux/user_syms.c
> +++ b/arch/um/os-Linux/user_syms.c
> @@ -27,10 +27,10 @@ EXPORT_SYMBOL(strstr);
>  #ifndef __x86_64__
>  extern void *memcpy(void *, const void *, size_t);
>  EXPORT_SYMBOL(memcpy);
> -#endif
> -
>  EXPORT_SYMBOL(memmove);
>  EXPORT_SYMBOL(memset);
> +#endif
> +
>  EXPORT_SYMBOL(printf);
>
>  /* Here, instead, I can provide a fake prototype. Yes, someone cares: genksyms.
> diff --git a/arch/x86/um/Makefile b/arch/x86/um/Makefile
> index 33c51c064c77..7dbd76c546fe 100644
> --- a/arch/x86/um/Makefile
> +++ b/arch/x86/um/Makefile
> @@ -26,7 +26,8 @@ else
>
>  obj-y += syscalls_64.o vdso/
>
> -subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o
> +subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o \
> +       ../lib/memmove_64.o ../lib/memset_64.o
>
>  endif
>
> diff --git a/arch/x86/um/vdso/Makefile b/arch/x86/um/vdso/Makefile
> index 0caddd6acb22..450efa0fb694 100644
> --- a/arch/x86/um/vdso/Makefile
> +++ b/arch/x86/um/vdso/Makefile
> @@ -3,6 +3,9 @@
>  # Building vDSO images for x86.
>  #
>
> +# do not instrument on vdso because KASAN is not compatible with user mode
> +KASAN_SANITIZE                 := n
> +
>  # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
>  KCOV_INSTRUMENT                := n
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..5b54f3c9a741 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -125,7 +125,7 @@ config KASAN_STACK_ENABLE
>
>  config KASAN_STACK
>         int
> -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> +       default 1 if (KASAN_STACK_ENABLE || CC_IS_GCC) && !UML
>         default 0
>
>  config KASAN_S390_4_LEVEL_PAGING
> --
> 2.25.0.265.gbab2e86ba0-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-%3Dw%40mail.gmail.com.
