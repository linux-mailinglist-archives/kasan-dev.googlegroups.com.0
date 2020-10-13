Return-Path: <kasan-dev+bncBD63HSEZTUIBBG5ASX6AKGQEDLLEZZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 42DE528C8DB
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Oct 2020 08:58:37 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id y7sf3771512pgg.12
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 23:58:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602572316; cv=pass;
        d=google.com; s=arc-20160816;
        b=UIMzyPSzAhOVs2GjoGvQbHz6caIOKi2O4lZkfsOj3GWlNY8aMRqgGC2sS4lM2/9cZ/
         rSNIGw0wGY9qlxxlpvqIEoJBxTpGOvGeNhsYlVQEUtEUXzlq+zkmw0tXDsPyCxKwmCw4
         OmMSm82evceND6Xq5ZPf10CglNIiNum4T3r3bPxV0oeSG7VUyoAV6DEOg/4boub/i1Yk
         tmPIfJjeipfBrE5kLzIUvJTwoQiZ1H3T00FzY7Vsw1ZDIRWG8Rt5Sy+aoIWqX2ALXnV+
         l3MBqfDaEhLEKO/bItK3/aWfG5fb9dPBXB/FtNBWeVcTrR5mz6jMrr1AWQ7kjQwSAhuG
         ZN7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=+Quj6vSL33WcSB/+KxdVOYtyy2mIjKtE8vPHo/sWXgk=;
        b=e2MwbAg2OI7vQsDzrH0dGNKO+Uxtg9e7uii/JWFnzYyjInRI7qpTFplL6ea+joPUUi
         vNB0fei3h7mpssOTHMZoVp68tCyDXlG8UbXUNg/it95bRTUPJ2nXZ4c21DTQYbVD7Ayx
         ny2yPn+hLH4DaF5kQYL98anqHR9KUclgLGACYHyzSVXsKiHg6ukeaJIpBJcsKsqcaC4J
         4gmNQIdCSeFyttJyniKwlwqq+M+4ikorKr4yrqEb2JvggYO4ksxWFSEhElwbpiBGqvlO
         nooeYazsSPduRZZ8N1y9d9bAkAWhSPA+YDWzMvcfgGljjhyc1T/ioyIEGJwRINn6c9Qx
         XEaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=VYTEMjwV;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Quj6vSL33WcSB/+KxdVOYtyy2mIjKtE8vPHo/sWXgk=;
        b=pb+Rdj1HWBQQX0RY9j1rT3B8pukUK1L6E0xolPZi1Uq2hG7ddYLG8HD6ttvW7YK/Yg
         KPCjmITMe/l6sKzPaPW8WKxGCA6otQccoH+8u2iGlF4v+TA1x3viheOuvBrP5949wLnA
         cbtvaJtFujurz/TINadTeUEbuwFT9ukbstMlsYnXj/PpXC3W6fV1Z2o9OPrOGeHfomG7
         jswKdU8r5gtTcPHIF+gsNJ48A4eCnWKghO9Eq6UhN6gGh2ubqkc0xgWDE81nsHvm8c3X
         HudQxUH1N7n0M9naxLNobTAf7Uwx8E6ixxPe65bE7st92uX9yRtnfHn6w47LB32vpWli
         ZM/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Quj6vSL33WcSB/+KxdVOYtyy2mIjKtE8vPHo/sWXgk=;
        b=ruCy3+JmmrflwPDodFMEegPh/sLE6Qg2Z7jguhjOPVjbP2R8InPvaYqrXZC97AKsXG
         Zwpis/+TyKYuvDsxDZ/cR7fi+UKB/wlniO5R5OB4E2wNeTKZWoyj6Pk68ukcFXTw2QY4
         XMjoHa6fDIUklzgjFbg7vvOZpxEY8iA6vfqfn/h1Mgifi9/N1usQJP9h6EAQAKUeNh4e
         uMEWdw4mQk3h2Uso571kIE8Gs726nIImmaOzMqV+G0tAWgvL24x0rexzShMFp4jPprO6
         bqT59/wwRuPUEYr62I3HRt8RUsPtoDs8HNMbDbE6mB+BZQuMwovaT5HZXNEej3bJl8VX
         oi1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iJ/CsSeWaAcVzfDTmDyyu9W0XBysY3UVa3SdRXJEgpzVP5h4Q
	LP6jMfEaY9GPy8Moog307qA=
X-Google-Smtp-Source: ABdhPJxUPHx496fdlC7WoYbde4NF9/itT1iUQtFIDBKxZR7UWuM/rzBGA0rkyLuWE06c48dijMkq0w==
X-Received: by 2002:a17:902:544:b029:d2:6379:a892 with SMTP id 62-20020a1709020544b02900d26379a892mr27018063plf.53.1602572315768;
        Mon, 12 Oct 2020 23:58:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1b4b:: with SMTP id b72ls6515370pfb.2.gmail; Mon, 12 Oct
 2020 23:58:35 -0700 (PDT)
X-Received: by 2002:a63:8c6:: with SMTP id 189mr16621126pgi.207.1602572314916;
        Mon, 12 Oct 2020 23:58:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602572314; cv=none;
        d=google.com; s=arc-20160816;
        b=jpgdAL6Yt3Rdse5DWjkMb+ayXp8PeT6X8xCG6HSy0gCtqHDFpjW3dMDhbcnbdSaf7h
         PXHql76pKGBt5EYgKRfcRtBCgATS5u2mdCLN9Ty1VJD6sdCstzRgkjz9d7lUgGt5qAUy
         QPHZjggURs7i7pWyTQgW83IuOUFCnmKToNUTmvREqkjtjzEp4sbXE9agiN/9kq66YhmL
         HJ6Gut7UNcE1NEZwvWn0A2N3cEP67onseF3JIos2XuBx6K9RA9kHhyOb517/IsQqblK0
         rOtZ0TzG88amTxLWwEl4avHoI4UlU5PlEK409JTOlIdbC9opajw4G4D8wpSaBpeQ0Cgr
         7SEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Px1524p8HwBsJ7drVwvc25s6beIW9w8XMfzjgYM7e4M=;
        b=0/9CvPTPEprF2GLIRxlIkbiz+r+DVIbbEa8Ggmzbavxts3Z88hG2iTI7pnTZG5OuDk
         Qq6j7Dl8g64OSdFXr82b/Rip0+BLmHSBf4VnlElSLbN9ATKP2GAiYZrdjYkIOnT0yCaM
         FhceQYd0FhlCnSVApBuWldnZu68c3INuIWmKmRX7e3JGlpuzjRPfbgrwbIs11Dnxkd4V
         E8uCraDgRTDbLccq69FxMhtc0Oy5fhou2rnsuh4ZUjhCMBidb/P2vW5gxBYtiWFOdCtb
         /1REtfayqfasqpetyYcyv7AVw13Hp8l12+bCSlQGMiaIkuNfnxNMR8CnYlSRF81hI+Fz
         Ih0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=VYTEMjwV;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mj1si1512069pjb.3.2020.10.12.23.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Oct 2020 23:58:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-ot1-f47.google.com (mail-ot1-f47.google.com [209.85.210.47])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 46724214DB
	for <kasan-dev@googlegroups.com>; Tue, 13 Oct 2020 06:58:34 +0000 (UTC)
Received: by mail-ot1-f47.google.com with SMTP id f37so18044081otf.12
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 23:58:34 -0700 (PDT)
X-Received: by 2002:a9d:6a85:: with SMTP id l5mr22141135otq.77.1602572313367;
 Mon, 12 Oct 2020 23:58:33 -0700 (PDT)
MIME-Version: 1.0
References: <20201012215701.123389-1-linus.walleij@linaro.org> <20201012215701.123389-5-linus.walleij@linaro.org>
In-Reply-To: <20201012215701.123389-5-linus.walleij@linaro.org>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Tue, 13 Oct 2020 08:58:22 +0200
X-Gmail-Original-Message-ID: <CAMj1kXGm0YsJwv6w3fkD1s8eUBKKtYUgEV3zqadziGGi7qGF2Q@mail.gmail.com>
Message-ID: <CAMj1kXGm0YsJwv6w3fkD1s8eUBKKtYUgEV3zqadziGGi7qGF2Q@mail.gmail.com>
Subject: Re: [PATCH 4/5 v15] ARM: Initialize the mapping of KASan shadow memory
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Russell King <linux@armlinux.org.uk>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Mike Rapoport <rppt@linux.ibm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=VYTEMjwV;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Hi Linus,

Just a couple of cosmetic tweaks below - no need to resend for this.

On Mon, 12 Oct 2020 at 23:59, Linus Walleij <linus.walleij@linaro.org> wrote:
>
> This patch initializes KASan shadow region's page table and memory.
> There are two stage for KASan initializing:
>
> 1. At early boot stage the whole shadow region is mapped to just
>    one physical page (kasan_zero_page). It is finished by the function
>    kasan_early_init which is called by __mmap_switched(arch/arm/kernel/
>    head-common.S)
>
> 2. After the calling of paging_init, we use kasan_zero_page as zero
>    shadow for some memory that KASan does not need to track, and we
>    allocate a new shadow space for the other memory that KASan need to
>    track. These issues are finished by the function kasan_init which is
>    call by setup_arch.
>
> When using KASan we also need to increase the THREAD_SIZE_ORDER
> from 1 to 2 as the extra calls for shadow memory uses quite a bit
> of stack.
>
> As we need to make a temporary copy of the PGD when setting up
> shadow memory we create a helpful PGD_SIZE definition for both
> LPAE and non-LPAE setups.
>
> The KASan core code unconditionally calls pud_populate() so this
> needs to be changed from BUG() to do {} while (0) when building
> with KASan enabled.
>
> After the initial development by Andre Ryabinin several modifications
> have been made to this code:
>
> Abbott Liu <liuwenliang@huawei.com>
> - Add support ARM LPAE: If LPAE is enabled, KASan shadow region's
>   mapping table need be copied in the pgd_alloc() function.
> - Change kasan_pte_populate,kasan_pmd_populate,kasan_pud_populate,
>   kasan_pgd_populate from .meminit.text section to .init.text section.
>   Reported by Florian Fainelli <f.fainelli@gmail.com>
>
> Linus Walleij <linus.walleij@linaro.org>:
> - Drop the custom mainpulation of TTBR0 and just use
>   cpu_switch_mm() to switch the pgd table.
> - Adopt to handle 4th level page tabel folding.
> - Rewrite the entire page directory and page entry initialization
>   sequence to be recursive based on ARM64:s kasan_init.c.
>
> Ard Biesheuvel <ardb@kernel.org>:
> - Necessary underlying fixes.
> - Crucial bug fixes to the memory set-up code.
>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Cc: Mike Rapoport <rppt@linux.ibm.com>
> Co-developed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Co-developed-by: Abbott Liu <liuwenliang@huawei.com>
> Co-developed-by: Ard Biesheuvel <ardb@kernel.org>
> Acked-by: Mike Rapoport <rppt@linux.ibm.com>
> Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
> Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
> Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
> Reported-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Ard Biesheuvel <ardb@kernel.org>
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> ---
> ChangeLog v14->v15:
> - Avoids reallocating KASAN blocks when a range gets
>   mapped twice - this occurs when mapping the DTB space explicitly.
> - Insert a missing TLB flush.
> - Move the cache flush after switching the MM (which makes logical
>   sense.
> - All these fixes discovered by Ard Bisheuvel.
> - Dropped the special mapping around the DTB after using Ard's
>   patches for remapping the DTB in a special memory area.
> - Add asmlinkage prototype for kasan_early_init() to get
>   rid of some compilation warnings.
> ChangeLog v13->v14:
> - Provide more elaborate prints of how virtual kernel memory
>   is mapped to the allocated lowmem pages.
> - Make sure to also map the memory around the __atags_pointer:
>   this memory is used for the device tree blob (DTB) and will be
>   accessed by the device tree parser. We were just lucky that
>   this was mostly in some acceptable memory location until now.
> ChangeLog v12->v13:
> - Rebase on kernel v5.9-rc1
> ChangeLog v11->v12:
> - Do not try to shadow highmem memory blocks. (Ard)
> - Provoke a build bug if the entire shadow memory doesn't fit
>   inside a single pgd_index() (Ard)
> - Move the pointer to (unsigned long) casts into the create_mapping()
>   function. (Ard)
> - After setting up the shadow memory make sure to issue
>   local_flush_tlb_all() so that we refresh all the global mappings. (Ard)
> - Simplify pte_populate() (Ard)
> - Skip over pud population as well as p4d. (Ard)
> - Drop the stop condition pmd_none(*pmdp) in the pmd population
>   loop. (Ard)
> - Stop passing around the node (NUMA) parameter in the init code,
>   we are not expecting any NUMA architectures to be introduced into
>   ARM32 so just hardcode NUMA_NO_NODE when calling
>   memblock_alloc_try_nid().
> ChangeLog v10->v11:
> - Fix compilation on LPAE systems.
> - Move the check for valid pgdp, pudp and pmdp into the loop for
>   each level moving over the directory pointers: we were just lucky
>   that we just needed one directory for each level so this fixes
>   the pmdp issue with LPAE and KASan now works like a charm on
>   LPAE as well.
> - Fold fourth level page directory (p4d) into the global page directory
>   pgd and just skip into the page upper directory (pud) directly. We
>   do not anticipate that ARM32 will every use 5-level page tables.
> - Simplify the ifdeffery around the temporary pgd.
> - Insert a comment about pud_populate() that is unconditionally called
>   by the KASan core code.
> ChangeLog v9->v10:
> - Rebase onto v5.8-rc1
> - add support for folded p4d page tables, use the primitives necessary
>   for the 4th level folding, add (empty) walks of p4d level.
> - Use the <linux/pgtable.h> header file that has now appeared as part
>   of the VM consolidation series.
> - Use a recursive method to walk pgd/p4d/pud/pmd/pte instead of the
>   separate early/main calls and the flat call structure used in the
>   old code. This was inspired by the ARM64 KASan init code.
> - Assume authorship of this code, I have now written the majority of
>   it so the blame is on me and noone else.
> ChangeLog v8->v9:
> - Drop the custom CP15 manipulation and cache flushing for swapping
>   TTBR0 and instead just use cpu_switch_mm().
> - Collect Ard's tags.
> ChangeLog v7->v8:
> - Rebased.
> ChangeLog v6->v7:
> - Use SPDX identifer for the license.
> - Move the TTBR0 accessor calls into this patch.
> ---
>  arch/arm/include/asm/kasan.h       |  33 ++++
>  arch/arm/include/asm/pgalloc.h     |   8 +-
>  arch/arm/include/asm/thread_info.h |   8 +
>  arch/arm/kernel/head-common.S      |   3 +
>  arch/arm/kernel/setup.c            |   2 +
>  arch/arm/mm/Makefile               |   3 +
>  arch/arm/mm/kasan_init.c           | 284 +++++++++++++++++++++++++++++
>  arch/arm/mm/pgd.c                  |  16 +-
>  8 files changed, 355 insertions(+), 2 deletions(-)
>  create mode 100644 arch/arm/include/asm/kasan.h
>  create mode 100644 arch/arm/mm/kasan_init.c
>
> diff --git a/arch/arm/include/asm/kasan.h b/arch/arm/include/asm/kasan.h
> new file mode 100644
> index 000000000000..303c35df3135
> --- /dev/null
> +++ b/arch/arm/include/asm/kasan.h
> @@ -0,0 +1,33 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * arch/arm/include/asm/kasan.h
> + *
> + * Copyright (c) 2015 Samsung Electronics Co., Ltd.
> + * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> + *
> + */
> +
> +#ifndef __ASM_KASAN_H
> +#define __ASM_KASAN_H
> +
> +#ifdef CONFIG_KASAN
> +
> +#include <asm/kasan_def.h>
> +
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +
> +/*
> + * The compiler uses a shadow offset assuming that addresses start
> + * from 0. Kernel addresses don't start from 0, so shadow
> + * for kernel really starts from 'compiler's shadow offset' +
> + * ('kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT)
> + */
> +
> +asmlinkage void kasan_early_init(void);
> +extern void kasan_init(void);
> +
> +#else
> +static inline void kasan_init(void) { }
> +#endif
> +
> +#endif
> diff --git a/arch/arm/include/asm/pgalloc.h b/arch/arm/include/asm/pgalloc.h
> index 15f4674715f8..fdee1f04f4f3 100644
> --- a/arch/arm/include/asm/pgalloc.h
> +++ b/arch/arm/include/asm/pgalloc.h
> @@ -21,6 +21,7 @@
>  #define _PAGE_KERNEL_TABLE     (PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_KERNEL))
>
>  #ifdef CONFIG_ARM_LPAE
> +#define PGD_SIZE               (PTRS_PER_PGD * sizeof(pgd_t))
>
>  static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
>  {
> @@ -28,14 +29,19 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
>  }
>
>  #else  /* !CONFIG_ARM_LPAE */
> +#define PGD_SIZE               (PAGE_SIZE << 2)
>
>  /*
>   * Since we have only two-level page tables, these are trivial
>   */
>  #define pmd_alloc_one(mm,addr)         ({ BUG(); ((pmd_t *)2); })
>  #define pmd_free(mm, pmd)              do { } while (0)
> +#ifdef CONFIG_KASAN
> +/* The KASan core unconditionally calls pud_populate() on all architectures */
> +#define pud_populate(mm,pmd,pte)       do { } while (0)
> +#else
>  #define pud_populate(mm,pmd,pte)       BUG()
> -
> +#endif
>  #endif /* CONFIG_ARM_LPAE */
>
>  extern pgd_t *pgd_alloc(struct mm_struct *mm);
> diff --git a/arch/arm/include/asm/thread_info.h b/arch/arm/include/asm/thread_info.h
> index 536b6b979f63..56fae7861fd3 100644
> --- a/arch/arm/include/asm/thread_info.h
> +++ b/arch/arm/include/asm/thread_info.h
> @@ -13,7 +13,15 @@
>  #include <asm/fpstate.h>
>  #include <asm/page.h>
>
> +#ifdef CONFIG_KASAN
> +/*
> + * KASan uses a lot of extra stack space so the thread size order needs to
> + * be increased.
> + */
> +#define THREAD_SIZE_ORDER      2
> +#else
>  #define THREAD_SIZE_ORDER      1
> +#endif
>  #define THREAD_SIZE            (PAGE_SIZE << THREAD_SIZE_ORDER)
>  #define THREAD_START_SP                (THREAD_SIZE - 8)
>
> diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
> index 6840c7c60a85..89c80154b9ef 100644
> --- a/arch/arm/kernel/head-common.S
> +++ b/arch/arm/kernel/head-common.S
> @@ -111,6 +111,9 @@ __mmap_switched:
>         str     r8, [r2]                        @ Save atags pointer
>         cmp     r3, #0
>         strne   r10, [r3]                       @ Save control register values
> +#ifdef CONFIG_KASAN
> +       bl      kasan_early_init
> +#endif
>         mov     lr, #0
>         b       start_kernel
>  ENDPROC(__mmap_switched)
> diff --git a/arch/arm/kernel/setup.c b/arch/arm/kernel/setup.c
> index 2a70e4958c14..43d033696e33 100644
> --- a/arch/arm/kernel/setup.c
> +++ b/arch/arm/kernel/setup.c
> @@ -59,6 +59,7 @@
>  #include <asm/unwind.h>
>  #include <asm/memblock.h>
>  #include <asm/virt.h>
> +#include <asm/kasan.h>
>
>  #include "atags.h"
>
> @@ -1139,6 +1140,7 @@ void __init setup_arch(char **cmdline_p)
>         early_ioremap_reset();
>
>         paging_init(mdesc);
> +       kasan_init();
>         request_standard_resources(mdesc);
>
>         if (mdesc->restart)
> diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
> index 99699c32d8a5..4536159bc8fa 100644
> --- a/arch/arm/mm/Makefile
> +++ b/arch/arm/mm/Makefile
> @@ -113,3 +113,6 @@ obj-$(CONFIG_CACHE_L2X0_PMU)        += cache-l2x0-pmu.o
>  obj-$(CONFIG_CACHE_XSC3L2)     += cache-xsc3l2.o
>  obj-$(CONFIG_CACHE_TAUROS2)    += cache-tauros2.o
>  obj-$(CONFIG_CACHE_UNIPHIER)   += cache-uniphier.o
> +
> +KASAN_SANITIZE_kasan_init.o    := n
> +obj-$(CONFIG_KASAN)            += kasan_init.o
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> new file mode 100644
> index 000000000000..22ac84defa5d
> --- /dev/null
> +++ b/arch/arm/mm/kasan_init.c
> @@ -0,0 +1,284 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +/*
> + * This file contains kasan initialization code for ARM.
> + *
> + * Copyright (c) 2018 Samsung Electronics Co., Ltd.
> + * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> + * Author: Linus Walleij <linus.walleij@linaro.org>
> + */
> +
> +#define pr_fmt(fmt) "kasan: " fmt
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memblock.h>
> +#include <linux/sched/task.h>
> +#include <linux/start_kernel.h>
> +#include <linux/pgtable.h>
> +#include <asm/cputype.h>
> +#include <asm/highmem.h>
> +#include <asm/mach/map.h>
> +#include <asm/memory.h>
> +#include <asm/page.h>
> +#include <asm/pgalloc.h>
> +#include <asm/procinfo.h>
> +#include <asm/proc-fns.h>
> +
> +#include "mm.h"
> +
> +static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
> +
> +pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
> +
> +static __init void *kasan_alloc_block(size_t size)
> +{
> +       return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
> +                                     MEMBLOCK_ALLOC_KASAN, NUMA_NO_NODE);
> +}
> +
> +static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
> +                                     unsigned long end, bool early)
> +{
> +       unsigned long next;
> +       pte_t *ptep = pte_offset_kernel(pmdp, addr);
> +
> +       do {
> +               pte_t entry;
> +               void *p;
> +
> +               next = addr + PAGE_SIZE;
> +
> +               if (!early) {
> +                       if (!pte_none(READ_ONCE(*ptep)))
> +                               continue;
> +
> +                       p = kasan_alloc_block(PAGE_SIZE);
> +                       if (!p) {
> +                               panic("%s failed to alloc pte for address 0x%lx\n",

This does not allocate a page table but a shadow page.

> +                                     __func__, addr);
> +                               return;
> +                       }
> +                       memset(p, KASAN_SHADOW_INIT, PAGE_SIZE);
> +                       entry = pfn_pte(virt_to_pfn(p),
> +                                       __pgprot(pgprot_val(PAGE_KERNEL)));
> +               } else if (pte_none(READ_ONCE(*ptep))) {
> +                       /*
> +                        * The early shadow memory is mapping all KASan
> +                        * operations to one and the same page in memory,
> +                        * "kasan_early_shadow_page" so that the instrumentation
> +                        * will work on a scratch area until we can set up the
> +                        * proper KASan shadow memory.
> +                        */
> +                       entry = pfn_pte(virt_to_pfn(kasan_early_shadow_page),
> +                                       __pgprot(_L_PTE_DEFAULT | L_PTE_DIRTY | L_PTE_XN));
> +               } else {
> +                       /*
> +                        * Early shadow mappings are PMD_SIZE aligned, so if the
> +                        * first entry is already set, they must all be set.
> +                        */
> +                       return;
> +               }
> +
> +               set_pte_at(&init_mm, addr, ptep, entry);
> +       } while (ptep++, addr = next, addr != end);
> +}
> +
> +/*
> + * The pmd (page middle directory) is only used on LPAE
> + */
> +static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
> +                                     unsigned long end, bool early)
> +{
> +       unsigned long next;
> +       pmd_t *pmdp = pmd_offset(pudp, addr);
> +
> +       do {
> +               if (pmd_none(*pmdp)) {
> +                       void *p = early ? kasan_early_shadow_pte :
> +                               kasan_alloc_block(PAGE_SIZE);
> +
> +                       if (!p) {
> +                               panic("%s failed to allocate pmd for address 0x%lx\n",

This allocates a block of PTEs

> +                                     __func__, addr);
> +                               return;
> +                       }
> +                       pmd_populate_kernel(&init_mm, pmdp, p);
> +                       flush_pmd_entry(pmdp);
> +               }
> +
> +               next = pmd_addr_end(addr, end);
> +               kasan_pte_populate(pmdp, addr, next, early);
> +       } while (pmdp++, addr = next, addr != end);
> +}
> +
> +static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
> +                                     bool early)
> +{
> +       unsigned long next;
> +       pgd_t *pgdp;
> +       p4d_t *p4dp;
> +       pud_t *pudp;
> +
> +       pgdp = pgd_offset_k(addr);
> +
> +       do {
> +               /* Allocate and populate the PGD if it doesn't already exist */
> +               if (!early && pgd_none(*pgdp)) {
> +                       void *p = kasan_alloc_block(PAGE_SIZE);
> +
> +                       if (!p) {
> +                               panic("%s failed to allocate pgd for address 0x%lx\n",

This allocates a block of P4D folded into PUD folded into PMD.

In summary, since the __func__ gives us the location of the error,
perhaps just drop the pgd here (and pmd above?)

> +                                     __func__, addr);
> +                               return;
> +                       }
> +                       pgd_populate(&init_mm, pgdp, p);
> +               }
> +
> +               next = pgd_addr_end(addr, end);
> +               /*
> +                * We just immediately jump over the p4d and pud page
> +                * directories since we believe ARM32 will never gain four
> +                * nor five level page tables.
> +                */
> +               p4dp = p4d_offset(pgdp, addr);
> +               pudp = pud_offset(p4dp, addr);
> +
> +               kasan_pmd_populate(pudp, addr, next, early);
> +       } while (pgdp++, addr = next, addr != end);
> +}
> +
> +extern struct proc_info_list *lookup_processor_type(unsigned int);
> +
> +void __init kasan_early_init(void)
> +{
> +       struct proc_info_list *list;
> +
> +       /*
> +        * locate processor in the list of supported processor
> +        * types.  The linker builds this table for us from the
> +        * entries in arch/arm/mm/proc-*.S
> +        */
> +       list = lookup_processor_type(read_cpuid_id());
> +       if (list) {
> +#ifdef MULTI_CPU
> +               processor = *list->proc;
> +#endif
> +       }
> +
> +       BUILD_BUG_ON((KASAN_SHADOW_END - (1UL << 29)) != KASAN_SHADOW_OFFSET);
> +       /*
> +        * We walk the page table and set all of the shadow memory to point
> +        * to the scratch page.
> +        */
> +       kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END, true);
> +}
> +
> +static void __init clear_pgds(unsigned long start,
> +                       unsigned long end)
> +{
> +       for (; start && start < end; start += PMD_SIZE)
> +               pmd_clear(pmd_off_k(start));
> +}
> +
> +static int __init create_mapping(void *start, void *end)
> +{
> +       void *shadow_start, *shadow_end;
> +
> +       shadow_start = kasan_mem_to_shadow(start);
> +       shadow_end = kasan_mem_to_shadow(end);
> +
> +       pr_info("Mapping kernel virtual memory block: %px-%px at shadow: %px-%px\n",
> +               start, end, shadow_start, shadow_end);
> +
> +       kasan_pgd_populate((unsigned long)shadow_start & PAGE_MASK,
> +                          (unsigned long)shadow_end, false);

As I mentioned in my reply to Florian, we should PAGE__ALIGN()
shadow_end here to ensure that we can meet the stop condition in
kasan_pgd_populate()

> +       return 0;
> +}
> +
> +void __init kasan_init(void)
> +{
> +       struct memblock_region *reg;
> +       int i;
> +
> +       /*
> +        * We are going to perform proper setup of shadow memory.
> +        *
> +        * At first we should unmap early shadow (clear_pgds() call bellow).
> +        * However, instrumented code can't execute without shadow memory.
> +        *
> +        * To keep the early shadow memory MMU tables around while setting up
> +        * the proper shadow memory, we copy swapper_pg_dir (the initial page
> +        * table) to tmp_pgd_table and use that to keep the early shadow memory
> +        * mapped until the full shadow setup is finished. Then we swap back
> +        * to the proper swapper_pg_dir.
> +        */
> +
> +       memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
> +#ifdef CONFIG_ARM_LPAE
> +       /* We need to be in the same PGD or this won't work */
> +       BUILD_BUG_ON(pgd_index(KASAN_SHADOW_START) !=
> +                    pgd_index(KASAN_SHADOW_END));
> +       memcpy(tmp_pmd_table,
> +              pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
> +              sizeof(tmp_pmd_table));
> +       set_pgd(&tmp_pgd_table[pgd_index(KASAN_SHADOW_START)],
> +               __pgd(__pa(tmp_pmd_table) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
> +#endif
> +       cpu_switch_mm(tmp_pgd_table, &init_mm);
> +       local_flush_tlb_all();
> +
> +       clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> +
> +       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> +                                   kasan_mem_to_shadow((void *)-1UL) + 1);
> +
> +       for_each_memblock(memory, reg) {
> +               void *start = __va(reg->base);
> +               void *end = __va(reg->base + reg->size);
> +
> +               /* Do not attempt to shadow highmem */
> +               if (reg->base >= arm_lowmem_limit) {
> +                       pr_info("Skip highmem block %px-%px\n",
> +                               start, end);

This gives me

[    0.000000] kasan: Skip highmem block 7f9db000-7fb9d000
[    0.000000] kasan: Skip highmem block 7fb9d000-c0000000

for

[    0.000000]   node   0: [mem 0x00000000ff9db000-0x00000000ffb9cfff]
[    0.000000]   node   0: [mem 0x00000000ffb9d000-0x000000023fffffff]

which is highly confusing - highmem does not have a VA in the first
place, so reporting it here makes no sense. Better use %llx here and
print reg->base/size directly.

> +                       continue;
> +               }
> +               if (reg->base + reg->size > arm_lowmem_limit) {
> +                       pr_info("Truncate memory block %px-%px\n to %px-%px\n",
> +                               start, end, start, __va(arm_lowmem_limit));

This gives me

[    0.000000] kasan: Truncate memory block c0000000-7f9db000
                to c0000000-f0000000
for

[    0.000000]   node   0: [mem 0x0000000040000000-0x00000000ff9dafff]

which is equally confusing. I think we should also use reg->base/size
here, and omit the start and __va(arm_lowmem_limit) entirely, and just
print something like

kasan: Truncating shadow for 0x0040000000-0x00ff9dafff to lowmem region

(note that 0x%10llx should be sufficient as LPAE addresses have at most 40 bits)



> +                       end = __va(arm_lowmem_limit);
> +               }
> +               if (start >= end) {
> +                       pr_info("Skipping invalid memory block %px-%px\n",
> +                               start, end);
> +                       continue;
> +               }
> +
> +               create_mapping(start, end);
> +       }
> +
> +       /*
> +        * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
> +        *    so we need to map this area.
> +        * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
> +        *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
> +        *    use kasan_populate_zero_shadow.
> +        */
> +       create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
> +
> +       /*
> +        * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
> +        * we should make sure that it maps the zero page read-only.
> +        */
> +       for (i = 0; i < PTRS_PER_PTE; i++)
> +               set_pte_at(&init_mm, KASAN_SHADOW_START + i*PAGE_SIZE,
> +                          &kasan_early_shadow_pte[i],
> +                          pfn_pte(virt_to_pfn(kasan_early_shadow_page),
> +                               __pgprot(pgprot_val(PAGE_KERNEL)
> +                                        | L_PTE_RDONLY)));
> +
> +       cpu_switch_mm(swapper_pg_dir, &init_mm);
> +       local_flush_tlb_all();
> +
> +       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +       pr_info("Kernel address sanitizer initialized\n");
> +       init_task.kasan_depth = 0;
> +}
> diff --git a/arch/arm/mm/pgd.c b/arch/arm/mm/pgd.c
> index c5e1b27046a8..f8e9bc58a84f 100644
> --- a/arch/arm/mm/pgd.c
> +++ b/arch/arm/mm/pgd.c
> @@ -66,7 +66,21 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>         new_pmd = pmd_alloc(mm, new_pud, 0);
>         if (!new_pmd)
>                 goto no_pmd;
> -#endif
> +#ifdef CONFIG_KASAN
> +       /*
> +        * Copy PMD table for KASAN shadow mappings.
> +        */
> +       init_pgd = pgd_offset_k(TASK_SIZE);
> +       init_p4d = p4d_offset(init_pgd, TASK_SIZE);
> +       init_pud = pud_offset(init_p4d, TASK_SIZE);
> +       init_pmd = pmd_offset(init_pud, TASK_SIZE);
> +       new_pmd = pmd_offset(new_pud, TASK_SIZE);
> +       memcpy(new_pmd, init_pmd,
> +              (pmd_index(MODULES_VADDR) - pmd_index(TASK_SIZE))
> +              * sizeof(pmd_t));
> +       clean_dcache_area(new_pmd, PTRS_PER_PMD * sizeof(pmd_t));
> +#endif /* CONFIG_KASAN */
> +#endif /* CONFIG_LPAE */
>
>         if (!vectors_high()) {
>                 /*
> --
> 2.26.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGm0YsJwv6w3fkD1s8eUBKKtYUgEV3zqadziGGi7qGF2Q%40mail.gmail.com.
