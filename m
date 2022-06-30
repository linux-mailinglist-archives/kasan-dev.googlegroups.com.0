Return-Path: <kasan-dev+bncBCMIZB7QWENRBPW76WKQMGQE2KNON6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 579405616A5
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 11:41:19 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id c187-20020a1c35c4000000b003970013833asf7759288wma.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 02:41:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656582079; cv=pass;
        d=google.com; s=arc-20160816;
        b=NiGbFSUjZ1gtDzqwwR32FPCLlLei2TucEvKA4gCUIcnv0why06PFUYRlESNdLYufAX
         BwIVRVp/rDcq+kCJW67mTXlQe8DdoIGHEST77efBG1ufRURDcQD6FUQvDERwyKaMLHnX
         l1SVpQwwtRvpNAYpitSfC8/tqGKpOoiXqf/wMMRodwwPMLK+AH0iVSVeIpNeaqdIUUqX
         6Ua8m5s0dr601XDD62zZeAbe75igHoC3rL7TuwWzonOhSb2foWcUyPZetAxSOMdDwQIA
         KVfousHBgql2IxofY09Xl1RnKLuU7w76ZIk6+h0iSzX6NfgUT1si0qmCdPYHJad59lMw
         +RWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rGdL9cufJQqAzbftnMXcNHGGoiTO86FNMoJpYITYmjg=;
        b=kPJXV1Mr4kWiTqybEO2BwMhkASCwgtYVjEda50YuyC1kJENnFyzCT+rQkww5FP9IYW
         yv1n0dfNPAkBT9q4vA1ooup8k0MzjWli3e7lvLOADJENbBluyIetWvtps9K/UcPBiXCV
         GNVehHMec+v2C13NzHvy+v5TtjZgRI/fJqoZ2rhOiPqF5A3YBNxEeFpCJLk2FdpQNBlT
         HVcV5fB6jy7+U+h9qr1LWa6tCtLSZRA0eaAmRjMZzXn4vFZIjTE5trmFKdhjeFesikwk
         2+pPBPpy0K8yVpCvU3b5Z+oJzkStX1PQXnrBTg0IJyd/lN6JgpbzIXJfC52F8Rz2B/nM
         9YZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y4rVKbnm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rGdL9cufJQqAzbftnMXcNHGGoiTO86FNMoJpYITYmjg=;
        b=a5KxHxJgxINJyGw0y1yJUc7zd/R3rvggZ6NAfEBzUCOz0D4Xla0HtDYSYBZvCM6fzx
         Zkii4FvGa0QjdMuN52vozzgxVL4KJh65dZuMDpxt505IaUUKw1oN1nfV0JKyQS11HK5F
         ImeS1GZQoxIG5QLKZCzChbRveEw2kwAzrK6gPkdAXRRj2owP1WK5Ent6+KdKJ0XcJIhr
         tolSeYVcgAPIGx5lrIKUGWm+f9MA/ShnnnLboxQcZxDIXwkelVkvqImdRHtS3cLXDKNJ
         vvPT7rkL8nyqbpD5XpQuJBo5vwIhIjYZ1ESOGtP/s0EH8q+oz+vtyuWviyEkAA5PGuw9
         sK0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rGdL9cufJQqAzbftnMXcNHGGoiTO86FNMoJpYITYmjg=;
        b=4Drr++c3CK35kY6P4djLMZ6yAeNo127TYQ341rCpFEt2AoZ3j2/kvAzBItH5Bofix1
         HraWXbLtcWzijUMOqs4FjzNyx8ETFfBlaHTcFmjUelK0JnyyPNzkuo9iHifrXLHWf1Jp
         TRsuF6e/LW6pQ0xJBhayVMOQZ0gweXfMoVhlPRzcAYlBojkaz/Cw2wxQhPPHiLBwnuC4
         7WoCtTkt0UUiF8TVcOgnu0iikAuX6pOHIDPu2mPKDGOgp0vy1DO04UNFdwCtinojKEmP
         mgB8gAFWFIgzYcHjonz1JLfL2bOrW4yvww2wLro+8Xhn4ANMa8GgARa1FoBEHYCgKPYX
         1cEA==
X-Gm-Message-State: AJIora8ylokEUnNiSPEAVde9vr4uXH+4T5Xi4UEz67NLVwQDeN8uoefk
	HSLAt0gjDE+LLvyKCe+WGmA=
X-Google-Smtp-Source: AGRyM1ssIy2xISItnmKkJTXgL4Bp6e2sJILGxDHHqnoDlG6I8eNaQT80mReJm/fJxcfXpj7+F8SI0A==
X-Received: by 2002:adf:dc0d:0:b0:21d:ea5:710f with SMTP id t13-20020adfdc0d000000b0021d0ea5710fmr7517866wri.48.1656582078840;
        Thu, 30 Jun 2022 02:41:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls5092620wrz.3.gmail; Thu, 30 Jun 2022
 02:41:17 -0700 (PDT)
X-Received: by 2002:a5d:4e84:0:b0:21b:bdda:4a06 with SMTP id e4-20020a5d4e84000000b0021bbdda4a06mr7685437wru.137.1656582077829;
        Thu, 30 Jun 2022 02:41:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656582077; cv=none;
        d=google.com; s=arc-20160816;
        b=KVK5fZwtq2VUveyVJv18IMZVeFd2KANbsPTm9/cKroklBmAK3EB9/smkiVpCjox1NA
         PkjPwFYsNixgQxXnLvfC++I/jjQl0GcnZ4hXzw2LgnuyJir60tOqIwYRsfA78c5hGMsE
         IrXcOg+PBXcxDDJmnRtFG4Dioz0MmvAi4lFtzTarFWs1uP4BaNkDMH++ANDnZU8KWQL3
         FatLYSOpB9XfW9lJciNpfD+2jthhn5aPggmRkD07jGAXujTutG1urx4Pd+2/psH3GwX1
         9lxTyKjgMqUcIfaOf5iC8M1e9RlCYeXsyXudjANF8p5UmP4kYYmLXSGUIhtwia9zCdpB
         vVFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wAVpu4PqqEDDZdXNb0Q5jWsifj6l0cepNEIgy3bnybo=;
        b=rD7obWakRpK4bPG9dbJYQaxXjPtgHP1thI/cokcGvg8wFxOZQsk31DqpRbvyc6JYeA
         68f2k7cexj/2jUTt2dJH6gW2iZPI/arbxX9T9LUOqk0mrX+zL6ODn/A7y4/L0df/U1CX
         sXgBgmhAqonDoD+JRAYI57fa11tU+8bVv3heLGxrIVQgtWp0yQI5A8Ly679ToLR4UbBK
         l39xCcaFr/yrL2u1iYGI7uq+sgDEfMz9NIqCZvN3ZN8nvw2Q5G4Z9aEH2tRm02SY+IzI
         MRF8Al10fyVGnCvuWtbR0FT1aGqwwX49be06Hhfdw/xVb+7DCztDnVgU1GxVj4yaC1D8
         5GwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y4rVKbnm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id x11-20020adfdccb000000b0021bbdc3209asi612367wrm.1.2022.06.30.02.41.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 02:41:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id e12so8429858lfr.6
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 02:41:17 -0700 (PDT)
X-Received: by 2002:a05:6512:2520:b0:47f:8512:19c1 with SMTP id
 be32-20020a056512252000b0047f851219c1mr4950575lfb.540.1656582076993; Thu, 30
 Jun 2022 02:41:16 -0700 (PDT)
MIME-Version: 1.0
References: <20220630080834.2742777-1-davidgow@google.com> <20220630080834.2742777-2-davidgow@google.com>
In-Reply-To: <20220630080834.2742777-2-davidgow@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Jun 2022 11:41:04 +0200
Message-ID: <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
To: David Gow <davidgow@google.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Brendan Higgins <brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, linux-mm@kvack.org, 
	kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Y4rVKbnm;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::131
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

On Thu, 30 Jun 2022 at 10:08, David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Make KASAN run on User Mode Linux on x86_64.
>
> The UML-specific KASAN initializer uses mmap to map the ~16TB of shadow
> memory to the location defined by KASAN_SHADOW_OFFSET.  kasan_init()
> utilizes constructors to initialize KASAN before main().
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the KASAN_SHADOW_OFFSET
> option. The default location of this offset is 0x100000000000, which
> keeps it out-of-the-way even on UML setups with more "physical" memory.
>
> For low-memory setups, 0x7fff8000 can be used instead, which fits in an
> immediate and is therefore faster, as suggested by Dmitry Vyukov. There
> is usually enough free space at this location; however, it is a config
> option so that it can be easily changed if needed.
>
> Note that, unlike KASAN on other architectures, vmalloc allocations
> still use the shadow memory allocated upfront, rather than allocating
> and free-ing it per-vmalloc allocation.
>
> If another architecture chooses to go down the same path, we should
> replace the checks for CONFIG_UML with something more generic, such
> as:
> - A CONFIG_KASAN_NO_SHADOW_ALLOC option, which architectures could set
> - or, a way of having architecture-specific versions of these vmalloc
>   and module shadow memory allocation options.
>
> Also note that, while UML supports both KASAN in inline mode
> (CONFIG_KASAN_INLINE) and static linking (CONFIG_STATIC_LINK), it does
> not support both at the same time.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Johannes Berg <johannes@sipsolutions.net>
> ---
> This is v4 of the KASAN/UML port. It should be ready to go, and is
> identical to v3 module a minor formatting error.
>
> Note that this will fail to build if UML is linked statically due to:
> https://lore.kernel.org/all/20220526185402.955870-1-davidgow@google.com/
>
> Changes since v3:
> https://lore.kernel.org/lkml/20220630074757.2739000-2-davidgow@google.com/
> - Fix some tabs which got converted to spaces by a rogue vim plugin.
>
> Changes since v2:
> https://lore.kernel.org/lkml/20220527185600.1236769-2-davidgow@google.com/
> - Don't define CONFIG_KASAN in USER_CFLAGS, given we dont' use it.
>   (Thanks Johannes)
> - Update patch descriptions and comments given we allocate shadow memory based
>   on the size of the virtual address space, not the "physical" memory
>   used by UML.
>   - This was changed between the original RFC and v1, with
>     KASAN_SHADOW_SIZE's definition being updated.
>   - References to UML using 18TB of space and the shadow memory taking
>     2.25TB were updated. (Thanks Johannes)
>   - A mention of physical memory in a comment was updated. (Thanks
>     Andrey)
> - Move some discussion of how the vmalloc() handling could be made more
>   generic from a comment to the commit description. (Thanks Andrey)
>
> Changes since RFC v3:
> https://lore.kernel.org/all/20220526010111.755166-1-davidgow@google.com/
> - No longer print "KernelAddressSanitizer initialized" (Johannes)
> - Document the reason for the CONFIG_UML checks in shadow.c (Dmitry)
> - Support static builds via kasan_arch_is_ready() (Dmitry)
> - Get rid of a redundant call to kasam_mem_to_shadow() (Dmitry)
> - Use PAGE_ALIGN and the new PAGE_ALIGN_DOWN macros (Dmitry)
> - Reinstate missing arch/um/include/asm/kasan.h file (Johannes)
>
> Changes since v1:
> https://lore.kernel.org/all/20200226004608.8128-1-trishalfonso@google.com/
> - Include several fixes from Vincent Whitchurch:
> https://lore.kernel.org/all/20220525111756.GA15955@axis.com/
> - Support for KASAN_VMALLOC, by changing the way
>   kasan_{populate,release}_vmalloc work to update existing shadow
>   memory, rather than allocating anything new.
> - A similar fix for modules' shadow memory.
> - Support for KASAN_STACK
>   - This requires the bugfix here:
> https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
>   - Plus a couple of files excluded from KASAN.
> - Revert the default shadow offset to 0x100000000000
>   - This was breaking when mem=1G for me, at least.
> - A few minor fixes to linker sections and scripts.
>   - I've added one to dyn.lds.S on top of the ones Vincent added.
>
> ---
>  arch/um/Kconfig                  | 15 +++++++++++++
>  arch/um/include/asm/common.lds.S |  2 ++
>  arch/um/include/asm/kasan.h      | 37 ++++++++++++++++++++++++++++++++
>  arch/um/kernel/Makefile          |  3 +++
>  arch/um/kernel/dyn.lds.S         |  6 +++++-
>  arch/um/kernel/mem.c             | 19 ++++++++++++++++
>  arch/um/os-Linux/mem.c           | 22 +++++++++++++++++++
>  arch/um/os-Linux/user_syms.c     |  4 ++--
>  arch/x86/um/Makefile             |  3 ++-
>  arch/x86/um/vdso/Makefile        |  3 +++
>  mm/kasan/shadow.c                | 29 +++++++++++++++++++++++--
>  11 files changed, 137 insertions(+), 6 deletions(-)
>  create mode 100644 arch/um/include/asm/kasan.h
>
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 8062a0c08952..289c9dc226d6 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -12,6 +12,8 @@ config UML
>         select ARCH_HAS_STRNLEN_USER
>         select ARCH_NO_PREEMPT
>         select HAVE_ARCH_AUDITSYSCALL
> +       select HAVE_ARCH_KASAN if X86_64
> +       select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ASM_MODVERSIONS
>         select HAVE_UID16
> @@ -220,6 +222,19 @@ config UML_TIME_TRAVEL_SUPPORT
>
>           It is safe to say Y, but you probably don't need this.
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x100000000000
> +       help
> +         This is the offset at which the ~16TB of shadow memory is
> +         mapped and used by KASAN for memory debugging. This can be any
> +         address that has at least KASAN_SHADOW_SIZE (total address space divided
> +         by 8) amount of space so that the KASAN shadow memory does not conflict
> +         with anything. The default is 0x100000000000, which works even if mem is
> +         set to a large value. On low-memory systems, try 0x7fff8000, as it fits
> +         into the immediate of most instructions, improving performance.
> +
>  endmenu
>
>  source "arch/um/drivers/Kconfig"
> diff --git a/arch/um/include/asm/common.lds.S b/arch/um/include/asm/common.lds.S
> index eca6c452a41b..fd481ac371de 100644
> --- a/arch/um/include/asm/common.lds.S
> +++ b/arch/um/include/asm/common.lds.S
> @@ -83,6 +83,8 @@
>    }
>    .init_array : {
>         __init_array_start = .;
> +       *(.kasan_init)
> +       *(.init_array.*)
>         *(.init_array)
>         __init_array_end = .;
>    }
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> new file mode 100644
> index 000000000000..0d6547f4ec85
> --- /dev/null
> +++ b/arch/um/include/asm/kasan.h
> @@ -0,0 +1,37 @@
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
> +extern int kasan_um_is_ready;
> +
> +#ifdef CONFIG_STATIC_LINK
> +#define kasan_arch_is_ready() (kasan_um_is_ready)
> +#endif
> +#else
> +static inline void kasan_init(void) { }
> +#endif /* CONFIG_KASAN */
> +
> +#endif /* __ASM_UM_KASAN_H */
> diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> index 1c2d4b29a3d4..a089217e2f0e 100644
> --- a/arch/um/kernel/Makefile
> +++ b/arch/um/kernel/Makefile
> @@ -27,6 +27,9 @@ obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
>  obj-$(CONFIG_STACKTRACE) += stacktrace.o
>  obj-$(CONFIG_GENERIC_PCI_IOMAP) += ioport.o
>
> +KASAN_SANITIZE_stacktrace.o := n
> +KASAN_SANITIZE_sysrq.o := n

Why are these needed?
It's helpful to leave some comments for any of *_SANITIZE:=n.
Otherwise later it's unclear if it's due to some latent bugs, some
inherent incompatibility, something that can be fixed, etc.

Otherwise the patch looks good to me.

> +
>  USER_OBJS := config.o
>
>  include arch/um/scripts/Makefile.rules
> diff --git a/arch/um/kernel/dyn.lds.S b/arch/um/kernel/dyn.lds.S
> index 2f2a8ce92f1e..2b7fc5b54164 100644
> --- a/arch/um/kernel/dyn.lds.S
> +++ b/arch/um/kernel/dyn.lds.S
> @@ -109,7 +109,11 @@ SECTIONS
>       be empty, which isn't pretty.  */
>    . = ALIGN(32 / 8);
>    .preinit_array     : { *(.preinit_array) }
> -  .init_array     : { *(.init_array) }
> +  .init_array     : {
> +    *(.kasan_init)
> +    *(.init_array.*)
> +    *(.init_array)
> +  }
>    .fini_array     : { *(.fini_array) }
>    .data           : {
>      INIT_TASK_DATA(KERNEL_STACK_SIZE)
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 15295c3237a0..276a1f0b91f1 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -18,6 +18,25 @@
>  #include <kern_util.h>
>  #include <mem_user.h>
>  #include <os.h>
> +#include <linux/sched/task.h>
> +
> +#ifdef CONFIG_KASAN
> +int kasan_um_is_ready;
> +void kasan_init(void)
> +{
> +       /*
> +        * kasan_map_memory will map all of the required address space and
> +        * the host machine will allocate physical memory as necessary.
> +        */
> +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +       init_task.kasan_depth = 0;
> +       kasan_um_is_ready = true;
> +}
> +
> +static void (*kasan_init_ptr)(void)
> +__section(".kasan_init") __used
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
> index ba5789c35809..f778e37494ba 100644
> --- a/arch/x86/um/Makefile
> +++ b/arch/x86/um/Makefile
> @@ -28,7 +28,8 @@ else
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
> index 5943387e3f35..8c0396fd0e6f 100644
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
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index a4f07de21771..0e3648b603a6 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -295,9 +295,22 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>                 return 0;
>
>         shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> -       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>         shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> -       shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +
> +       /*
> +        * User Mode Linux maps enough shadow memory for all of virtual memory
> +        * at boot, so doesn't need to allocate more on vmalloc, just clear it.
> +        *
> +        * The remaining CONFIG_UML checks in this file exist for the same
> +        * reason.
> +        */
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset((void *)shadow_start, KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
> +               return 0;
> +       }
> +
> +       shadow_start = PAGE_ALIGN_DOWN(shadow_start);
> +       shadow_end = PAGE_ALIGN(shadow_end);
>
>         ret = apply_to_page_range(&init_mm, shadow_start,
>                                   shadow_end - shadow_start,
> @@ -466,6 +479,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>
>         if (shadow_end > shadow_start) {
>                 size = shadow_end - shadow_start;
> +               if (IS_ENABLED(CONFIG_UML)) {
> +                       __memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
> +                       return;
> +               }
>                 apply_to_existing_page_range(&init_mm,
>                                              (unsigned long)shadow_start,
>                                              size, kasan_depopulate_vmalloc_pte,
> @@ -531,6 +548,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>         if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
>                 return -EINVAL;
>
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset((void *)shadow_start, KASAN_SHADOW_INIT, shadow_size);
> +               return 0;
> +       }
> +
>         ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
>                         shadow_start + shadow_size,
>                         GFP_KERNEL,
> @@ -554,6 +576,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>
>  void kasan_free_module_shadow(const struct vm_struct *vm)
>  {
> +       if (IS_ENABLED(CONFIG_UML))
> +               return;
> +
>         if (vm->flags & VM_KASAN)
>                 vfree(kasan_mem_to_shadow(vm->addr));
>  }
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZahTu0pGNSdZmx%3D4ZJHt4%3DmVuhxQnH_7ykDA5_fBJZVQ%40mail.gmail.com.
