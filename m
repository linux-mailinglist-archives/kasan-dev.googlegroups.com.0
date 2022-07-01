Return-Path: <kasan-dev+bncBCMIZB7QWENRB7437OKQMGQEK77VMWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D18A563182
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 12:35:44 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id e10-20020a19674a000000b0047f8d95f43csf978214lfj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 03:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656671743; cv=pass;
        d=google.com; s=arc-20160816;
        b=dF+PxJUVVow01Wn+yrcK1U8yApOr1/94LeLTwZwib4PilVaDN8A65lQX8zYSI/OQK7
         SWShTersyBP38bXZxErTKs7EBpvvTUcmmGbj3hu4Bhb+AvbT4gIfzXVGr4T6U7uz5QQK
         1/qO89akPLSFk0kifdyzRi1WAvvKQBOEhZjHELZ3FcbAMD9P6UHA6KSu4iUzmiMTAPNH
         GXZN8DVE41guqG0cfHhz6ZG1+98dkvGxTeo9ejFfsQPspo0TGIOyJ2HOmnJnaV+cAF2g
         Q20ZgTKs6PxSmybouBdc3YiDBFKTxVQCtq3T9aDVV2whSgQO46qY8jUbLE+LAujkhDCZ
         xVSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8Cfd+ozsktfDKXXH4m5gt4X/qodn+z3iir+NYU0woLQ=;
        b=OYQYdP0xWBNRIDN+Zt5jzNg5TSCK1X8XauCLmY89BLtkNalvJ5M/yYA7Xj9JNz3Pxg
         KHBlUaI++1aqScKh4qF4qqqxa56vNERxJkG5mrKTHbKwTvQ971cD4eXP+z5ETr9OR6TG
         X6a7YYfxjNHVu4f3cnxaC5rFSpfysVcJYmI67QvHMzA1+Wha0POobtd832yzghfiNmf6
         pKzcdUjDMbh8RUDixUfkpJi3SLiHVfw5C5l1Ce+Z0rdH4iVktPMLI7QZmoZCqgTL1GbO
         7E6R5IZIpxTxvzwjj68t5UqFDlAXt3pDOwkqcdQRwsuKwQ3KPKtBflwEFophTbaHkGUJ
         4SrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qEpF28uX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Cfd+ozsktfDKXXH4m5gt4X/qodn+z3iir+NYU0woLQ=;
        b=cMFEaFk3weLCrC7RYjwEkVoE7gRdlWjIhhZCqNio7jUK2fTs3EXo0dw9RYIB/6n19p
         gf1uODfea8e8Tq/IFqb4EjoIhNWazHpZDem8c7DnkvIMxUiCjk6NmdGUn4cp18SY7Jyu
         wufb5quGHLyctv7hG1rAyFbtNZ+YcSbPAYcDI/fWZu02wCCnRDNpQTt59P9n+m5a9Q5b
         6uII/cgw1Lh0VPi/Yz3E0SOIUqsaS++fS61hMMZpHXuD93knIKab/YyvIgzwHR9X/da0
         D/xTZG2gAQon5ZDRB2BwJsS0Zm9NouDf2C6yScl2LCxNhap2ITrVKCDsLDCfzmZefD8M
         3cJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Cfd+ozsktfDKXXH4m5gt4X/qodn+z3iir+NYU0woLQ=;
        b=rOuHjg/7sckTDJtU0ptJt3JWeyKmR7O61fwz6m8G/H0hlg6myzf5Mcc3yTKIDp/n1z
         I/ZELmhHFUyaqObp+M1hLL03dXUKYSZoEXSkk5G6ZUbodV+BtVi1NMCkuHZNNvOJJYU3
         C85UeZh6jOML6U8z0+GS+YWVcu5M1EPMTRjZQAlLcVRtaM5MP9hJ6wMnUjnCikBvEepU
         dy0vnmNNpLuvmvy8E945KsgcrllmiKk4dT5IgnIM0dLx91OICR3+xspOnu/QnOzcM/vU
         njhsuLLA+vW75bRsAjChZh6xBBZ6XGHLcnB4B8LxUBpSHvZaZjRFPgVmXXp5w8wknsnB
         H1+Q==
X-Gm-Message-State: AJIora+alMRAuDmJhbohicp0jF4xGxsa5SxmGziMpbu7bSdtkAOZ2VOG
	525dNjv8p5qwidBuHAP1gGA=
X-Google-Smtp-Source: AGRyM1t9PydRvtuLDqTMbtME1sv67ZuysnJ1kEZAG3id/CBf/1gTdq1adk2T/o+MEV/atI05RZaLSQ==
X-Received: by 2002:a2e:6a03:0:b0:25b:f8cf:8e39 with SMTP id f3-20020a2e6a03000000b0025bf8cf8e39mr4243124ljc.166.1656671743640;
        Fri, 01 Jul 2022 03:35:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls506700lfv.3.gmail; Fri, 01 Jul 2022
 03:35:42 -0700 (PDT)
X-Received: by 2002:a05:6512:3088:b0:47f:77df:45be with SMTP id z8-20020a056512308800b0047f77df45bemr9258134lfd.134.1656671742460;
        Fri, 01 Jul 2022 03:35:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656671742; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJW2EOBb0fDQ/LFPBG6N2dmBHekHFsVohaQ1Eu4BPiNOM58mdryRO0lSW7I3NEwy3W
         2nrdcxREtBjxLzBamcDjZNa2NifjObBJYDfnGJtX+CpceccfQxUl0hYNRGdYPFB2H08f
         erHZhN6KbADBb/Pazpg6Epxj68jNtCm7MXiOmQjauQtsy8pb06WkhmNsPl4aeGZMrpXW
         +/aExscDrOJmytt7vYPSs/hjhNfASEp3x7KziU1NooPvLEJOsptWVI8IQdsO5Rg/4CUh
         DeNk8G8u3cfcQQCoBuisWYij5Sk00UNEs/PxpwLrn+8dgsq1CW/XnS//FX/HX6yJhp7z
         A+8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fQXZH2JUAWT13GOyjsNXdXYnf19cCsULvonMxNIOPU4=;
        b=W3zLeTr9CInUKRYS4mXLNch8ULQqjUHbQoM3CXlIsMigE38swCYY36Oo+J7MVAcuex
         OHRL2B1DfsXoHWikDWZw6chmIfiG9gEHR1Xf/bGAkrIa7+XZUPgEzo8rf9s/IrlvvpIO
         j1HMf4+wXL0lfr0J0GUvv/tMHCn4fuboc3quQL0n/v0YLVYvYQ8W6d5UrDjdWBPg0or3
         cL3NEAC6jRX6nvt/eqLVXCCkXadV+e4F9W31nyFU5HtoBbKQXMnl230wtrfgKRzfB03E
         m1Pq6+TP57iW1iuRUs7skocHkYTvy+ydLkW0lgIILtrDAGq7teSTrATn8XOLFNqd0JPb
         /JyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qEpF28uX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id o19-20020ac24c53000000b004810d3e125csi739684lfk.11.2022.07.01.03.35.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 03:35:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id l7so1363921ljj.4
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 03:35:42 -0700 (PDT)
X-Received: by 2002:a2e:bd0e:0:b0:25a:88b3:9af6 with SMTP id
 n14-20020a2ebd0e000000b0025a88b39af6mr8084677ljq.363.1656671741903; Fri, 01
 Jul 2022 03:35:41 -0700 (PDT)
MIME-Version: 1.0
References: <20220701091621.3022368-1-davidgow@google.com> <20220701091621.3022368-2-davidgow@google.com>
In-Reply-To: <20220701091621.3022368-2-davidgow@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Jul 2022 12:35:30 +0200
Message-ID: <CACT4Y+ZxtoPdVHKoy+het63rym2F52YZehw=Ev+0YkGQ=7+7Vw@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] UML: add support for KASAN under x86_64
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
 header.i=@google.com header.s=20210112 header.b=qEpF28uX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234
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

On Fri, 1 Jul 2022 at 11:16, David Gow <davidgow@google.com> wrote:
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


> ---
> This is v5 of the KASAN/UML port. It should be ready to go (this time,
> for sure! :-))
>
> Note that this will fail to build if UML is linked statically due to:
> https://lore.kernel.org/all/20220526185402.955870-1-davidgow@google.com/
>
> Changes since v4:
> https://lore.kernel.org/lkml/20220630080834.2742777-2-davidgow@google.com/
> - Instrument all of the stacktrace code (except for the actual reading
>   of the stack frames).
>   - This means that stacktrace.c and sysrq.c are now instrumented.
>   - Stack frames are read with READ_ONCE_NOCHECK()
>   - Thanks Andrey for pointing this out.
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
>  arch/um/kernel/dyn.lds.S         |  6 +++++-
>  arch/um/kernel/mem.c             | 19 ++++++++++++++++
>  arch/um/kernel/stacktrace.c      |  2 +-
>  arch/um/os-Linux/mem.c           | 22 +++++++++++++++++++
>  arch/um/os-Linux/user_syms.c     |  4 ++--
>  arch/x86/um/Makefile             |  3 ++-
>  arch/x86/um/vdso/Makefile        |  3 +++
>  mm/kasan/shadow.c                | 29 +++++++++++++++++++++++--
>  11 files changed, 135 insertions(+), 7 deletions(-)
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
> diff --git a/arch/um/kernel/stacktrace.c b/arch/um/kernel/stacktrace.c
> index 86df52168bd9..fd3b61b3d4d2 100644
> --- a/arch/um/kernel/stacktrace.c
> +++ b/arch/um/kernel/stacktrace.c
> @@ -27,7 +27,7 @@ void dump_trace(struct task_struct *tsk,
>
>         frame = (struct stack_frame *)bp;
>         while (((long) sp & (THREAD_SIZE-1)) != 0) {
> -               addr = *sp;
> +               addr = READ_ONCE_NOCHECK(*sp);
>                 if (__kernel_text_address(addr)) {
>                         reliable = 0;
>                         if ((unsigned long) sp == bp + sizeof(long)) {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZxtoPdVHKoy%2Bhet63rym2F52YZehw%3DEv%2B0YkGQ%3D7%2B7Vw%40mail.gmail.com.
