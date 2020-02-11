Return-Path: <kasan-dev+bncBCMIZB7QWENRBDGMRLZAKGQETIUZNJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 409E7158F69
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 14:03:10 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id j142sf5918160oib.23
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 05:03:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581426189; cv=pass;
        d=google.com; s=arc-20160816;
        b=KgWah1qkNVIyPG2tuubQpiT/7nF6qVHGHfkBuFLDZcFnpyZ7MoMCqJYCXjSmQdr0lr
         mH/PP4rfpDSBym+SMJYTLMtFBoafwuILYq9fkiJR8ik/ys+2nsqf2qrjK2PyjBcZ1Pei
         mWd4JSN0IYQG8GDGX4h1Q55yK0NZVmj2f+qBo5N7HfDXbNLHhXKfouW1b84yY5oGcWBB
         l2aIE4oIsPHdDWogDMKLmcyHnKeY1aSSoT8+wleUubYGIKkfxlGoTmvI9MloD/dLSKbh
         Yv+k0IQhnGAVq48Z+BDNrRI0jKP4xrvDiwHHx2kb95BqzdYfmSu5mv7Gm+CsDJvg2dXS
         Bf8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3vxCNlWJkkkTR4dm2ZqkOk5Uk1Frk407y14lWkJrH8Q=;
        b=PR29Y0dVBGrgdtmK/YTD8aTyxeJBfjB5F1YE5ee+xEl/9dt3J/Dm6M7QAklr5O/4gk
         NgItRTNBvYDHOGiAkv+xp0GIZVh/H3vlt0Bv6d0lL8TcgaYif7AfEo8k8UdScExKYcEq
         jxDKqONdjfaAD3ouC7DO1R0zqlxfSA50BPfvWkACVNhDf8QGIh+VeIvbVxpD0vOJzNXu
         6EnZ1D/rByip/UkVMRh8vXwsFGuXBzLQIRDd9rh5836PxzMW00YFkKIb1N3oTSWN8Ijv
         th1yblKxaGvavPcQ6MIT6HFEy+XiBKAXPhdHWL7IEceiw7yWQ8BZszY2IggAJb2GoJ/8
         jwXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WxJg/u6N";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3vxCNlWJkkkTR4dm2ZqkOk5Uk1Frk407y14lWkJrH8Q=;
        b=UM2yXtoA7g4t+UbMEfIb5RU6gJUk4p7VbMyD1novR0qfEBwzpx5gNMZ+B723p0+6vr
         +vw4/YDPKK8dsf6UnSh96+DyjLx/gOxv6vI0h0xjY7Kz99L/3su5aL3Daz7EK8JrP3h7
         rtr8uEMUjuz3OLxCV9+ulr4prydJVka/DgOrEG/k2jb3vNX9ASuYJ4HVM/UgHTQdK2xB
         G65R5jLuo2Jzt7gPNGtxlVc4pgKj4vtULqFqhSJhiyi0x2520OnHJbGPjXlp2xens0KX
         SZAKKad+XF5MAh0F9Nvc+R5dfvEJ6iSq50Qbu6oPNsX3xsfFsYOSoKT4zA19X2rb8qEI
         +IRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3vxCNlWJkkkTR4dm2ZqkOk5Uk1Frk407y14lWkJrH8Q=;
        b=IfKVjCtDyPflY2ko/5lme6Of4A28gn17Qqd+fXDlUkPt8qlbra61EAHf0QwoqHgp5i
         BANCWErn/SNRMAlxkGGLdMJTm65qPFEfXbFAy/E2AzWlVjX5SOqR005iBD0o8JQHUHyH
         1zwv55Li5zwfr+LZqTbgOC+nAZlktEn0Q/FMUf2g0B5qHssfwnG2TNAE4aq26oONhMGL
         NfS0YMiHkTRs7YXZhSfh/pL1AYaSEdKtBiKwo25w2gOOPMSBZvL/YyezlAMigbT+m/uj
         Y1oqejNCv7qCh2RzsRGHj4D+XRHbtFPugmet36fOdVE8fhll6CkTVWJicDCHCkzrr8ji
         x/Ng==
X-Gm-Message-State: APjAAAW/JJCbpo/u6kMZUyvoi/inma3APvMZ2IFhlv664K8SmnZJFtba
	yrAxOGqfA9ZFZQzjFE7RJRk=
X-Google-Smtp-Source: APXvYqyCUqRnJDtnfkhMo6evuFrL3kg72HLkog9dlkqg+4Xjj4lgbUT5NCJKhFAffyS1/HLv9VOTcw==
X-Received: by 2002:aca:ea46:: with SMTP id i67mr2681265oih.149.1581426188787;
        Tue, 11 Feb 2020 05:03:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7281:: with SMTP id t1ls3277112otj.7.gmail; Tue, 11 Feb
 2020 05:03:08 -0800 (PST)
X-Received: by 2002:a9d:7498:: with SMTP id t24mr5236786otk.290.1581426188363;
        Tue, 11 Feb 2020 05:03:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581426188; cv=none;
        d=google.com; s=arc-20160816;
        b=B/77OIC+4cEMDKWLtidZNgAyKwPB9LI4AD117DPqHn3jKWInrG9eLmg+rePT4vUWC1
         BjtY+8/vUiMPA9GjPMsLIAD3hOcV4gL/FYZUWlLgsHu7hhuszGismvca+5x/MZ2gyGqV
         8LPSM4jLmzFyZS6S2r95I6n/wgQsLeNH2KnfBZW8mhCRldFcA0SIfLhk3acSuElB1jEi
         z7iaE8KQCYayr2H/xUYlhKXRIu8jxEImaGLJz5+z2pjRQR89w7vyjKpVP3WiXzthgPUa
         DxSJYdk64rUVNS/hHhKD4K8nK8CZ8vZfDrh1S0lJot1M//blZU4/mGA/7FjkK5hqPLpL
         S71A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bas+/VrzdMy27Ru/nYIGc/kjNJVzSRBJ3GgmNCXPKdM=;
        b=HTsjnS/OFKjIxkITOGTsUlA3ADuucgFAdvdN6pHWLPFNFYGe1Q89UugGEpkWZIVG7d
         /WIN7jO3UFoncYQuP4ia0uEZ9UhoZHpznp9bzHpiO4OEbSudvEd2+OrVzIJOVeS8X3Pf
         BoZbDnbUBRCR+C8VV8hRhyk1NtHqolUH4m176tI9OAE+vgWe0nbx4Q+vfduk8vWMWvu+
         /qiN/yMtq6tQeiVkzSYRjXEZI4rCrzKi5HIbRUWYTSXZYUxYpiKRQcHPhH4fnfarDMaE
         rp/Z62/J4I5BamN7X33C4EritsNOQPcUCCMMyrNOxh4oMVVUc0tFyeuW0KbUKDozFDYI
         9zwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WxJg/u6N";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id b2si192619oib.5.2020.02.11.05.03.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 05:03:08 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id r5so6482239qtt.9
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 05:03:08 -0800 (PST)
X-Received: by 2002:ac8:7159:: with SMTP id h25mr2278562qtp.380.1581426187228;
 Tue, 11 Feb 2020 05:03:07 -0800 (PST)
MIME-Version: 1.0
References: <20200210225806.249297-1-trishalfonso@google.com>
In-Reply-To: <20200210225806.249297-1-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Feb 2020 14:02:55 +0100
Message-ID: <CACT4Y+Y=Qj6coWpY107Dj+TsUJK1nruWAC=QMZBDC5snNZRTOw@mail.gmail.com>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Johannes Berg <johannes@sipsolutions.net>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="WxJg/u6N";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Mon, Feb 10, 2020 at 11:58 PM 'Patricia Alfonso' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Make KASAN run on User Mode Linux on x86_64.
>
> Depends on Constructor support in UML and is based off of
> "[RFC PATCH] um: implement CONFIG_CONSTRUCTORS for modules"
> (https://patchwork.ozlabs.org/patch/1234551/) and "[DEMO] um:
> demonstrate super early constructors"
> (https://patchwork.ozlabs.org/patch/1234553/) by
> Johannes.
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the
> KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
> space, and KASAN requires 1/8th of this. The default location of
> this offset is 0x100000000000. There is usually enough free space at
> this location; however, it is a config option so that it can be
> easily changed if needed.
>
> The UML-specific KASAN initializer uses mmap to map
> the roughly 2.25TB of shadow memory to the location defined by
> KASAN_SHADOW_OFFSET.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
>
> Changes since v1:
>  - KASAN has been initialized much earlier.
>  - With the help of Johannes's RFC patch to implement constructors in
>    UML and Demo showing how kasan_init could take advantage of these
>    super early constructors, most of the "KASAN_SANITIZE := n" have
>    been removed.
>  - Removed extraneous code
>  - Fixed typos


I started reviewing this, but I am spotting things that I already
commented on, like shadow start and about shadow size const. Please
either address them, or answer why they are not addressed, or add some
kind of TODOs so that I don't write the same comment again.


>  arch/um/Kconfig              | 10 ++++++++++
>  arch/um/Makefile             |  6 ++++++
>  arch/um/include/asm/dma.h    |  1 +
>  arch/um/include/asm/kasan.h  | 30 ++++++++++++++++++++++++++++++
>  arch/um/kernel/Makefile      | 22 ++++++++++++++++++++++
>  arch/um/kernel/mem.c         | 19 +++++++++----------
>  arch/um/os-Linux/mem.c       | 19 +++++++++++++++++++
>  arch/um/os-Linux/user_syms.c |  4 ++--
>  arch/x86/um/Makefile         |  3 ++-
>  arch/x86/um/vdso/Makefile    |  3 +++
>  10 files changed, 104 insertions(+), 13 deletions(-)
>  create mode 100644 arch/um/include/asm/kasan.h
>
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 0917f8443c28..2b76dc273731 100644
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
> @@ -200,6 +201,15 @@ config UML_TIME_TRAVEL_SUPPORT
>
>           It is safe to say Y, but you probably don't need this.
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x100000000000
> +       help
> +         This is the offset at which the ~2.25TB of shadow memory is
> +         initialized and used by KASAN for memory debugging. The default
> +         is 0x100000000000.
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
> diff --git a/arch/um/include/asm/dma.h b/arch/um/include/asm/dma.h
> index fdc53642c718..8aafd60d62bb 100644
> --- a/arch/um/include/asm/dma.h
> +++ b/arch/um/include/asm/dma.h
> @@ -5,6 +5,7 @@
>  #include <asm/io.h>
>
>  extern unsigned long uml_physmem;
> +extern unsigned long long physmem_size;
>
>  #define MAX_DMA_ADDRESS (uml_physmem)
>
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> new file mode 100644
> index 000000000000..ba08061068cf
> --- /dev/null
> +++ b/arch/um/include/asm/kasan.h
> @@ -0,0 +1,30 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_UM_KASAN_H
> +#define __ASM_UM_KASAN_H
> +
> +#include <linux/init.h>
> +#include <linux/const.h>
> +
> +#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +#ifdef CONFIG_X86_64
> +#define KASAN_SHADOW_SIZE 0x100000000000UL
> +#else
> +#error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
> +#endif /* CONFIG_X86_64 */
> +
> +// used in kasan_mem_to_shadow to divide by 8
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +
> +#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
> +#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> +
> +#ifdef CONFIG_KASAN
> +void kasan_init(void);
> +#else
> +static inline void kasan_init(void) { }
> +#endif /* CONFIG_KASAN */
> +
> +void kasan_map_memory(void *start, unsigned long len);
> +void kasan_unpoison_shadow(const void *address, size_t size);
> +
> +#endif /* __ASM_UM_KASAN_H */
> diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> index 5aa882011e04..875e1827588b 100644
> --- a/arch/um/kernel/Makefile
> +++ b/arch/um/kernel/Makefile
> @@ -8,6 +8,28 @@
>  # kernel.
>  KCOV_INSTRUMENT                := n
>
> +# The way UMl deals with the stack causes seemingly false positive KASAN
> +# reports such as:
> +# BUG: KASAN: stack-out-of-bounds in show_stack+0x15e/0x1fb
> +# Read of size 8 at addr 000000006184bbb0 by task swapper/1
> +# ==================================================================
> +# BUG: KASAN: stack-out-of-bounds in dump_trace+0x141/0x1c5
> +# Read of size 8 at addr 0000000071057eb8 by task swapper/1
> +# ==================================================================
> +# BUG: KASAN: stack-out-of-bounds in get_wchan+0xd7/0x138
> +# Read of size 8 at addr 0000000070e8fc80 by task systemd/1
> +#
> +# With these files removed from instrumentation, those reports are
> +# eliminated, but KASAN still repeatedly reports a bug on syscall_stub_data:
> +# ==================================================================
> +# BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x299/0x2bf
> +# Read of size 128 at addr 0000000071457c50 by task swapper/1
> +
> +KASAN_SANITIZE_stacktrace.o := n
> +KASAN_SANITIZE_sysrq.o := n
> +KASAN_SANITIZE_process.o := n
> +
> +
>  CPPFLAGS_vmlinux.lds := -DSTART=$(LDS_START)           \
>                          -DELF_ARCH=$(LDS_ELF_ARCH)     \
>                          -DELF_FORMAT=$(LDS_ELF_FORMAT) \
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 32fc941c80f7..7b7b8a0ee724 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -18,21 +18,20 @@
>  #include <kern_util.h>
>  #include <mem_user.h>
>  #include <os.h>
> +#include <linux/sched/task.h>
>
> -extern int printf(const char *msg, ...);
> -static void early_print(void)
> +#ifdef CONFIG_KASAN
> +void kasan_init(void)
>  {
> -       printf("I'm super early, before constructors\n");
> +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +       init_task.kasan_depth = 0;
> +       os_info("KernelAddressSanitizer initialized\n");
>  }
>
> -static void __attribute__((constructor)) constructor_test(void)
> -{
> -       printf("yes, you can see it\n");
> -}
> -
> -static void (*early_print_ptr)(void)
> +static void (*kasan_init_ptr)(void)
>  __attribute__((section(".kasan_init"), used))
> - = early_print;
> += kasan_init;
> +#endif
>
>  /* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
>  unsigned long *empty_zero_page = NULL;
> diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
> index 3c1b77474d2d..da7039721d35 100644
> --- a/arch/um/os-Linux/mem.c
> +++ b/arch/um/os-Linux/mem.c
> @@ -17,6 +17,25 @@
>  #include <init.h>
>  #include <os.h>
>
> +/**
> + * kasan_map_memory() - maps memory from @start with a size of @len.
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
> +                0) == MAP_FAILED)
> +               os_info("Couldn't allocate shadow memory %s", strerror(errno));
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
> --
> 2.25.0.341.g760bfbb309-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210225806.249297-1-trishalfonso%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY%3DQj6coWpY107Dj%2BTsUJK1nruWAC%3DQMZBDC5snNZRTOw%40mail.gmail.com.
