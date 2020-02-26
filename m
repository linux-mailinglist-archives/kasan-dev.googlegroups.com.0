Return-Path: <kasan-dev+bncBCMIZB7QWENRBSM33LZAKGQEPMZA44Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 29A6D170249
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 16:24:58 +0100 (CET)
Received: by mail-yw1-xc37.google.com with SMTP id c68sf4605623ywa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 07:24:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582730697; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZgL87yj3gQx7C9ULJwgngEGdV6bfAGaAnoySvCXN1ml1gVBeKxJPN61rWraXsEduyg
         h4kXe+jDqv0jCmW1A82pwz6R4NWSHeMj5UNEQdjNL1gji+wPC+NXeRfnGOZXt5FxtQcL
         u4czKf+SnmqHoV4AWGkiV+iySxMGdwluJeIYC/0EB+AhpCi46Jw+wwZ3Yk0+3/JXrulf
         xJjj26U77bjcWmv23N6uKCq5Zi73F+88dTrppC0MPfGy7wRkyUWMbRaidFn3/6vR8HdZ
         ctJ+Q+nVk0Gifz2Zm4ipTY5/A0ZbZ80aWqGS3XN0dBx3v0qi1ad4Vf86UdoT9K2dio9d
         eHmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9MujILcP5opeC4EiZrzwzbzAVZkwFMyUBOS0Fxxha2o=;
        b=wkGSyBrA7OdmVg7RS2FPimX26Es/LjmJ/h24bu0w8rifnnHu5MqgYPv3lVu/ux/Qo5
         d+fA1ZiDqI4JrDO8Ajb74AROTLrKy3fo4mZqdwD57GXkFvs0wlx9LV/zJveecsby1vnB
         Ir2ajNDeslh/HBJNDVsA20rvKZwMwHYcQ6W1Ft2xmC9Gu7APUySLiFE9NIxNK5clBQ5r
         Vrj5rEhocHiX3y2F8GiY1BBNY3A0rZO1kQSvT/B+Rqu2iQErd/52EBazVDwMtWSroejx
         ViN5CpAalIcki/G3w6awN+JEJNhVr5j0q/pqgL3rtf3PfJLMQxmiW9ww8QBufZwibNGO
         L1BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cn+ekfMz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9MujILcP5opeC4EiZrzwzbzAVZkwFMyUBOS0Fxxha2o=;
        b=rbDoAsV2qZZcpdZHPQYuB9scW7Ges8SEdtjYbepMuTWy7uzesiwVWxVCyzwxZiyJJ6
         aLfaqwubl8YSo+K7cAU33hSq91SpajLx1vnYCsD3LEwUx8pT8tqU4pRKIBa5DbDymP7F
         SHvkRdIYAJd8SxOB+5Z7Ltt1oUSpbqAUF/wvdwmSSgN9t1tVmpm/WNm9AP05bfr/QTGJ
         KqsqDSX+jgdUW56kadpnBfH0cPFDiDG2TZGfddtIloUgBHGGrYFyJpObvBCHw57coFiR
         Bj/EaDhcfqjYerF3IeZ8kiDafCslav4IYYgy6Gsi3/7oNEWU8+do77WmiMRV7ehTe8/M
         dfcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9MujILcP5opeC4EiZrzwzbzAVZkwFMyUBOS0Fxxha2o=;
        b=SVZ0sSacBus4zsU+HTVTr7I7Qt6c7HtE341Uoe3NKqD8YaRgILyGLna586+K+MVISu
         Jgq3Vr8G64Zo0opEwJ6TxDEtp/j8yc2sv7Cw9IstG8lzWA52Pbn5I1gtXO+nd4WVYz7v
         rhll8GtmEsdXOtYkpgwyUU45xv2FDqVMrL6naHgBaCivgFGY+Gz68aHMGMm3sojQyhfV
         tV+Z0yl6IFn01Bo0sE3LnCvBw7dQIz9zPmt/VWrfmkJESDIwQjgyevUhqfT/EJ8NSYsu
         8T8zhHjpO42SN6QOE5jzxfwLAMoPK4D4669i1e2dITo9caArDFQcv/0LsWBu8Sr9XqcT
         sJww==
X-Gm-Message-State: APjAAAUid/05z4PhPVgBINeu1Y5Z3JycHslKQj0lLg8ZIheG1Q49curs
	bVYHNXmYrEHRN0jLML6kkyQ=
X-Google-Smtp-Source: APXvYqzc0zwX98bKdyDoMgpkYH0sImsKp3NlOF6EBTXol9RmuDM/08VsIPTE+mXziSzE4CVuijnK4Q==
X-Received: by 2002:a25:4e02:: with SMTP id c2mr4978944ybb.504.1582730697129;
        Wed, 26 Feb 2020 07:24:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:6854:: with SMTP id d81ls750949ywc.11.gmail; Wed, 26 Feb
 2020 07:24:56 -0800 (PST)
X-Received: by 2002:a81:1054:: with SMTP id 81mr4383722ywq.57.1582730696809;
        Wed, 26 Feb 2020 07:24:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582730696; cv=none;
        d=google.com; s=arc-20160816;
        b=fj0mR1/a9FRuzXheNr8fN2Yac5DxgWBFs6/8uKMQ+IGlne9WYyv2C0y+6mPs9qunj0
         ofNXuHXVlzvtqaI9aBneYXSdJeA08eK+E2YviPXBHbssJaiMHY3e7FQPsHzKlvVxp0VN
         10dNDfTxhYdpQ0F7OPWyhnFdZQULGwPnZq5WqolLZ3aZvs6R0HiCu1kswDtupBNNwEV2
         4Nai5fvJrsamg8h8WyBdOeRvAMhQTZfWlIyiPWU0c6O8z+NaKhdyn/+tMLKHC+aLH4tj
         V1ZgMgYcB0Rn4LJlKeSCwyNIQH7mjIXPydcR6kzDEezRcc8qX2OX7FN3iXXrHsYaTgBs
         +AxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SmEQan0IvPFz83EOuHDD+3Su5OB9M2Qz6TI84c9YxRQ=;
        b=Y+82QBUNeZMy6QiX6SEVlHXyQkTHhukDAh0cnTgnJa6Ia73oiiUGW9SvQ5NGJ8VN2z
         d+kqzaCH8cUhOB+H05VKVKx29WWPoBtMT29wL3tXNAPdV6oFt6hPPTBczGr8prac+RHC
         tp8D+gqk+BzwRk/UmjOdqXgoD7zaOZ4kMZVa1qjIy7mus1PMF2ChXq0TFnpycA0wHsKU
         AheHQarM6KRYkW5mdbJox9rQSvFT3mtGzvbqNkugWckfEk/P/DSNp0j2WyWt5xXCFTnN
         Qe0bIeixNXHxtgcvv6dfKwq0VxeP7XW6V7vHGafQDzEod3ovKEKgD1gc6qCxx2jZ/qvG
         Nagw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cn+ekfMz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id d80si45589ywb.2.2020.02.26.07.24.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2020 07:24:56 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id o28so2951681qkj.9
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2020 07:24:56 -0800 (PST)
X-Received: by 2002:a37:88b:: with SMTP id 133mr5370841qki.256.1582730695156;
 Wed, 26 Feb 2020 07:24:55 -0800 (PST)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
In-Reply-To: <20200226004608.8128-1-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Feb 2020 16:24:44 +0100
Message-ID: <CACT4Y+at=Yr98sWub_QH_08dyN96jiDCjhCLhqXO3W9i1xPv+A@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Johannes Berg <johannes@sipsolutions.net>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cn+ekfMz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Feb 26, 2020 at 1:46 AM Patricia Alfonso
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

This now looks much better, cleaner, nicer and simpler.
There are few UML-specific things I did not understand, but I will
leave them to UML reviewers.
For KASAN-specifics:

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks!

> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bat%3DYr98sWub_QH_08dyN96jiDCjhCLhqXO3W9i1xPv%2BA%40mail.gmail.com.
