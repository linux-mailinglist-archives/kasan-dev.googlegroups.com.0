Return-Path: <kasan-dev+bncBD63HSEZTUIBBS5IWX6AKGQEJB6H4BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 171292923F6
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:54:37 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id b5sf4507460plk.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 01:54:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603097675; cv=pass;
        d=google.com; s=arc-20160816;
        b=DVu0FcAzBHGQgyEdUbmri64aDtpY/Is1zWVzlgAXbkmph0jlv+vdfNkV3bRYT4P6h7
         yemsCh8lIHjKfPNKkpyJ5l9isOECVcylEJs6Vc4LEpSehIyBFDvUsmfHChk+PGr/T4fr
         jTZxPMWumH6Nnm5kQuglvyi0F+3umEptlQkoSOtUkMG74bG3wpNS3bI7H8s2P6xkWWI4
         HMv/Gg63OUBKwSZU2d+2kGjequ3g/d5VRjxZYqrer1giwVA9XnpDHy8kVlDp8CWnKdc9
         o77VhBcFXe+qOXR7M/KBaV4aYZ0hcCDXeJ/SCsQszXe1dgIVGlLaPL2Wl1nGxyNpJa8S
         IQzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=TLMGt2o4TfyNe04nuFqQJvHHWIbKrVm/60SO3H0tHOg=;
        b=wSid0LJ3lucu0U576VyuxmDQRaM7GMaXRkLM/Xo/9vaFDu8YgnoIq3mRtOh5Kbk7ng
         lP5NvPuYJFRaLS8OzAs66BOn7xlFoCMLfoMMk1VWAPkY3KTTLS1BuWtsDksXeFAfmMf5
         ydy/DGTKdna8Yv6C8hr22kSomb2bY1OhfjcfsPtuHI3RVE24jz6WbleYj2yY/kAJfnrF
         U3mFv2F66crS6kHwcmVPGXtGaMziW/SN/XkulF8N3lp43pAhmWXDdNEOpQyOvku6CBIX
         yV45kJLL9D0W4TJPgseYaEWyfO5JEuDHs+I+iycm4bqctLUxS6QDjqsUgZXmWGz7jXo6
         30cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=lrzvy9ax;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TLMGt2o4TfyNe04nuFqQJvHHWIbKrVm/60SO3H0tHOg=;
        b=jVQqW8T2zi9s8PuAcvCDKsLOK4Xto8DddU92aPV2bnEoJwIwaQcMW8sixku0GuEm/6
         w7gYbGHsrmcj+mpkYkTZtH4gkYT3K3NKoS6kAaF8DVrPYgC6whGD/a702aWnaENIBtMd
         RW9AxjRvw9DY3hRtdmMlQJQ+a9rr+mypE9Wtt5ARbAGRISDmovtmod9gR98c5HGjl4EP
         BcoMGHZoblNXLsmslQi5dJsszqY0JCI2rBVcKAObWyX4rcur5pP8P+6Db4IFVaJqjvm5
         UGo53FM6/x3uTmxQpn3L4k2xXo/CcBixiFFF8IJ6T+4s4S72I2jmcqt2fVGELw9UQQSL
         pK0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TLMGt2o4TfyNe04nuFqQJvHHWIbKrVm/60SO3H0tHOg=;
        b=qwmQROM1GnTK6rCy292U4ANWeRtImTEEM6vCKS7EIjdWWGuhYrSV3YegvNvPTk6EzC
         A3idvKkhSLOjzeHqvGwyvuazz6MQdwxViImx77kV1gm7kZCwMqQM3h2fn7fW71pHLHhH
         t1HHTRGMhifjh25U86nPu85bKwVqF7blPb6LKXafFadUlstjgpvFm+Z4DkQP7LFkZo+i
         bGLV4zY0oyiPPYyP6biffLlXHfcD4OCLTqoJLXNEMl4VxBIta8hzsuObQ/UWhtHhh0yF
         gEE2VpWy38G62a88HSe1xAwgb13DxZaEh4CTRGTPJifP0VXfbc9LA55RyVzK3nrppeUA
         3FUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308V8qzErx+uxrBuDOtN1LvNGIOeoUhow39dQGdxpUknFmZ2/rF
	jdsjptCjrkFdWSmTkGAwmCY=
X-Google-Smtp-Source: ABdhPJz34qvIeHMSvQm26OqwjcYLKHuNV4tl1p9WBDnGpoDwHrtqz/8VHQEFSi0+00qWlGemMi0SWg==
X-Received: by 2002:a05:6a00:2386:b029:156:533:f982 with SMTP id f6-20020a056a002386b02901560533f982mr15795737pfc.77.1603097675237;
        Mon, 19 Oct 2020 01:54:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8810:: with SMTP id c16ls3362598pfo.10.gmail; Mon, 19
 Oct 2020 01:54:34 -0700 (PDT)
X-Received: by 2002:a63:d19:: with SMTP id c25mr13690918pgl.208.1603097674659;
        Mon, 19 Oct 2020 01:54:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603097674; cv=none;
        d=google.com; s=arc-20160816;
        b=vLaBzV1qcLs9uPtF4EhVih1o3bG+FdkeBe0KC5HZjTkTr088xzKCK4qjeQQloXCXlv
         RLqOgyOUID/LRPuYCXh7hDM37UHbXoA+T5M0RAWHirkT7ShagAbN6KXA8eCSdkxPehXs
         iYGhE/s10YC4+uPjP/5+re//h3wHCoAsJxEjyOGRoc+rTjSG5JtwHWk4TR1AUb3EoZc6
         vny53iJEj91B/igbw36A3cV+GNAW0+J8qWhZnhtDx83woPLGRRxMSeLQSQsv3ZbeP2/V
         YlSCud3kcviaQ0twEqTfW8W7NnkbN050Cp2I1lNEYOrrVPI9IG5u0BMc9PyV/2SbSbWS
         eN5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9Z3DOdX2gFf5vg0fwiF4AwnIg9bfufRdhwiR8Ce6sNo=;
        b=go4Kgghxc1hAcJHTcXbfX1Y7Iury1Giwz1Vrokybs2T6v5hsVXI1HQfhQGTxUPL076
         avDQ6hNKl6nnfgGLwycnnjDYmlnFcMBNrb9UNbs3RgGvN7OXoe7NYRfjM8UhYwoORWw3
         1T05sSAU/0lDH8VpZHhbSVNgwAmGwZogtp9OLNaSasq3FcplQkl8UPiHdtQgqpotnoiB
         bPXHeqGoy6/o691LA1698QBtE99fOnSGl1W6Y3R4n8NrXjA6sfgf0PzrZjHE/rB9fcmH
         +YZXlbYktlsiv8uTxlnfCNxPDAI7DHYGJNsW46dxltkNOPXDzpm2K1B+wQtF5EMquADi
         Hwfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=lrzvy9ax;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id cq16si690500pjb.2.2020.10.19.01.54.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Oct 2020 01:54:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-ot1-f51.google.com (mail-ot1-f51.google.com [209.85.210.51])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 15CC022282
	for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 08:54:34 +0000 (UTC)
Received: by mail-ot1-f51.google.com with SMTP id f37so9750041otf.12
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 01:54:34 -0700 (PDT)
X-Received: by 2002:a9d:6c92:: with SMTP id c18mr10727720otr.108.1603097673190;
 Mon, 19 Oct 2020 01:54:33 -0700 (PDT)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org> <20201019084140.4532-5-linus.walleij@linaro.org>
In-Reply-To: <20201019084140.4532-5-linus.walleij@linaro.org>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 19 Oct 2020 10:54:22 +0200
X-Gmail-Original-Message-ID: <CAMj1kXGay73yW0nsxp+trzNwFezhG6dBNYxip_s6u3CgHD+O8w@mail.gmail.com>
Message-ID: <CAMj1kXGay73yW0nsxp+trzNwFezhG6dBNYxip_s6u3CgHD+O8w@mail.gmail.com>
Subject: Re: [PATCH 4/5 v16] ARM: Initialize the mapping of KASan shadow memory
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Russell King <linux@armlinux.org.uk>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Mike Rapoport <rppt@linux.ibm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=lrzvy9ax;       spf=pass
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

On Mon, 19 Oct 2020 at 10:42, Linus Walleij <linus.walleij@linaro.org> wrote:
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
> Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
> Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
> Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
> Reported-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Ard Biesheuvel <ardb@kernel.org>
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> ---
...
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> new file mode 100644
> index 000000000000..8afd5c017b7f
> --- /dev/null
> +++ b/arch/arm/mm/kasan_init.c
> @@ -0,0 +1,292 @@
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
> +                               panic("%s failed to allocate shadow page for address 0x%lx\n",
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
> +                       /*
> +                        * We attempt to allocate a shadow block for the PMDs
> +                        * used by the PTEs for this address if it isn't already
> +                        * allocated.
> +                        */
> +                       void *p = early ? kasan_early_shadow_pte :
> +                               kasan_alloc_block(PAGE_SIZE);
> +
> +                       if (!p) {
> +                               panic("%s failed to allocate shadow block for address 0x%lx\n",
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
> +               /*
> +                * Allocate and populate the shadow block of p4d folded into
> +                * pud folded into pmd if it doesn't already exist
> +                */
> +               if (!early && pgd_none(*pgdp)) {
> +                       void *p = kasan_alloc_block(PAGE_SIZE);
> +
> +                       if (!p) {
> +                               panic("%s failed to allocate shadow block for address 0x%lx\n",
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
> +                          PAGE_ALIGN((unsigned long)shadow_end), false);
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
> +                       pr_info("Skip highmem block %pap-%pap\n",
> +                               &reg->base, &reg->base + reg->size);

Adding reg->size to &reg->base is not going to produce the expected
value here. I think we can just drop it, and only keep the start
address here (same below)

> +                       continue;
> +               }
> +               if (reg->base + reg->size > arm_lowmem_limit) {
> +                       pr_info("Truncating shadow for %pap-%pap to lowmem region\n",
> +                               &reg->base, &reg->base + reg->size);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGay73yW0nsxp%2BtrzNwFezhG6dBNYxip_s6u3CgHD%2BO8w%40mail.gmail.com.
