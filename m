Return-Path: <kasan-dev+bncBD63HSEZTUIBBIN7WX6AKGQEMWZMAQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 32D352924C7
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 11:42:59 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id s130sf1895926vsc.13
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 02:42:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603100578; cv=pass;
        d=google.com; s=arc-20160816;
        b=DFcWxBA9IMRre6lnef7FN9r9e4QAFGtqvLXlYwa7twASXGNwUCKsuPqshQgwiO8gCJ
         tdq39A58yDZ0rBoNDGmhr/5g0w0VLtjWAw//jDzvJwqd9PpwjLK2Xb4L6MAnq4KaCfPj
         OarTgcmb/kNUUSLsuJ1nkvM76BxQVtFdho7JSYKjPTQAefyUEZbt3Wv4qIaWPsyY9RHf
         KO7hkQNM/gu0NIeIqv0QPHJV3ggquzSQINzbP+KowdZCJZeKsAmr7wtrDRQmEZ2NoJ1F
         raZN8T4J4XcO/85TCqbBmIWqq/fn4VlRHTw10Gnk7BAJ+X0meKJbQ1yLwvvbeFQzDJl6
         JJdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=+CL++7gBk080ZxzPedDK5A314di5KeEjvNNBgNJ7K3I=;
        b=Ln/ojzKGTm/CQZJ6hCbgadGNhnv/KHyIrSyCyOp7LxYbcuLgO8U+b2yjYMWhW81MgQ
         PI4uqy45xVF7lGZ9OkbZpXgT7zsFoghOZtNejNP03YnxaQqZyS9BSTqw031B/mXPFRcT
         hL9h0aZ1JpU1yzasIAGBTyWVYwUoixbFUdXsRQY9VCTMhxi1vUkSPIhT1ewOqv+mtK1w
         qKMeVD3maRgcqMy1HXlcsCdxO2fGDRefCSHxDx4p9WLH6IjdB7DxfkgBbARL3ygwP2qI
         2Ao5IFmOuId3To7d7mLBiq9mvEMGzoSMORHQkYMXOU3iKe5anwBSo/R2helU1JkQxb2H
         4I6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hPqK6zMb;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+CL++7gBk080ZxzPedDK5A314di5KeEjvNNBgNJ7K3I=;
        b=a1GRpZwa7Gljeti3vzSLC40L1sJ3OUrCY6VoasbEXNEY6BRT6Y4J+o55Wv6laxt1Kj
         E91Wfjiumoi4MF2lYX/gK93K3kMHTq6dneTu5Zuq0rbpIfmw7eBBr/48i7fvLtvtH5eN
         3gVVWWP8jmj+znQwj7qfxtj7py1vUWfoZXtocEnWArAUpKYJw0QnEhs6Q/kvECOLPQSp
         /iTqNNkAySoKwUu0MwdMd+qG7vjiNVNydJ1qhW16nSsn/Ttek6E0qsmSlyn8849bZf5A
         YT6k3rZgZNUhW2J581Bh/9uy5YEPKsBALHNgj6bbctazXJI8P9jFRdVABoCDu+vXgHT3
         HS6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+CL++7gBk080ZxzPedDK5A314di5KeEjvNNBgNJ7K3I=;
        b=MqE+KTaeZn0OACLAHqlNKekV5dJTTZzftqAnfJ/+cLf8LkKtBPAPPx1jq3o6ypdqOV
         VTyt0WStqvI92oUEx/AwC6IiY/wDW6uvgmuCcWqqAUKZ3H9wicbW4H6Mq+waHmDGFItn
         yK5brNo5cOjRnkw5EildY+qtZI/G7+UmHcIWi4GLEPXJymP2hjCmQnmf27PMPEsruHbw
         z9T7Iqx/JMUC/UF7t8EcrJhjC56c+s/fR7qEz8m0IOjMX3QN4Nd9V6Et5dQuOYww3DoA
         XgPQ7azRIA18WnPz1hw0yJrZPlnP0wHbFBIAGpEp8iDbd5HH7qYKQf+qGWgZD6Iln7Uq
         8CFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mXh/mvcol2dnLCZIiy/5luYzliiuiW13LWwQhGZ1Lq3z8cRak
	qxCDkyymsFGZv7daOZMZRZg=
X-Google-Smtp-Source: ABdhPJybid7UhP7rK4Pi18b1NudODxALgVSrSiBH0pqkiLEiNWZccoVkxjmcVEe8WXVbmOA+zZCdpA==
X-Received: by 2002:a67:314a:: with SMTP id x71mr8378234vsx.24.1603100578062;
        Mon, 19 Oct 2020 02:42:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7005:: with SMTP id k5ls581637ual.2.gmail; Mon, 19 Oct
 2020 02:42:57 -0700 (PDT)
X-Received: by 2002:ab0:2087:: with SMTP id r7mr6690866uak.47.1603100577622;
        Mon, 19 Oct 2020 02:42:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603100577; cv=none;
        d=google.com; s=arc-20160816;
        b=v82TvgZFS9cM3usUJY+bTtaYdvdVfXBTCZ17jG+4cq5IYL6rz3Nx8qrYDCOpWc17VW
         88C1RpTZHJpvsy5F6HXi9w4AwV/lUEYDXAWS5hsGFdLxqHsoe6HcMB2jVIc5ypnH67K4
         p+s60oN82FR1E+CM1Kws/seBNXe5Ppv8AX30JQVpHND0NVXM96I4ycEjpIBLq+LTfoJA
         V+tSZR0CyQyZGf+CLErPSeHWK9RZkUSTG+mL4Xnx1MobO3YPCF7U/2z93lBaALxtWF2+
         KnTztIpPhxP4a5RCNwZLy4SL0LejcjAsJtZs9J2pHW9q6XEyDXh08US7bZola6giGg8V
         i4MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i0bjLSrDWi1ePThttlchA/1c2feth6tT+1yu3M+f2RY=;
        b=bfg110JxukqustMtj8AJbuPHUNrO6znmRVUBpSoaPuSbh4GWG2kISneSmcH7wbWtMf
         utYm04y0rElq9Vkvd2Uoyi5h4G0li5xbq38z/cxVRAWWEfAe3Htz6BUGxcywScB+bH4D
         xB0EZ7G6qS6WKQKBQY7XopCvpzE+VSweDMltkOCzNOrTqZ77SpH2dNgUczfw4neGdYsM
         pRi37PVMznCAHwF3wsq9kma6LAlN4NT0dtLMtBTd5Fv7NH5KICTc7hi4bTGk3VgnC3KM
         YSC+eD1bEU6c4yqsGcFR+pECc988O2wE50G7UAYdDHmZSTKjqnRIqmtPc4V12f66cguQ
         CSrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hPqK6zMb;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b16si215578vkn.5.2020.10.19.02.42.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Oct 2020 02:42:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-ot1-f47.google.com (mail-ot1-f47.google.com [209.85.210.47])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 31BE122263
	for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 09:42:56 +0000 (UTC)
Received: by mail-ot1-f47.google.com with SMTP id h62so6078724oth.9
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 02:42:56 -0700 (PDT)
X-Received: by 2002:a05:6830:4028:: with SMTP id i8mr10567748ots.90.1603100575355;
 Mon, 19 Oct 2020 02:42:55 -0700 (PDT)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-5-linus.walleij@linaro.org> <20201019093421.GA455883@linux.ibm.com>
In-Reply-To: <20201019093421.GA455883@linux.ibm.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 19 Oct 2020 11:42:44 +0200
X-Gmail-Original-Message-ID: <CAMj1kXGgrtj79UQ7Ei5NEEQ1_ALTJRVALFnjOmhZLb_4tSHauQ@mail.gmail.com>
Message-ID: <CAMj1kXGgrtj79UQ7Ei5NEEQ1_ALTJRVALFnjOmhZLb_4tSHauQ@mail.gmail.com>
Subject: Re: [PATCH 4/5 v16] ARM: Initialize the mapping of KASan shadow memory
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Russell King <linux@armlinux.org.uk>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=hPqK6zMb;       spf=pass
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

On Mon, 19 Oct 2020 at 11:37, Mike Rapoport <rppt@linux.ibm.com> wrote:
>
> On Mon, Oct 19, 2020 at 10:41:39AM +0200, Linus Walleij wrote:
> > This patch initializes KASan shadow region's page table and memory.
> > There are two stage for KASan initializing:
> >
> > 1. At early boot stage the whole shadow region is mapped to just
> >    one physical page (kasan_zero_page). It is finished by the function
> >    kasan_early_init which is called by __mmap_switched(arch/arm/kernel/
> >    head-common.S)
> >
> > 2. After the calling of paging_init, we use kasan_zero_page as zero
> >    shadow for some memory that KASan does not need to track, and we
> >    allocate a new shadow space for the other memory that KASan need to
> >    track. These issues are finished by the function kasan_init which is
> >    call by setup_arch.
> >
> > When using KASan we also need to increase the THREAD_SIZE_ORDER
> > from 1 to 2 as the extra calls for shadow memory uses quite a bit
> > of stack.
> >
> > As we need to make a temporary copy of the PGD when setting up
> > shadow memory we create a helpful PGD_SIZE definition for both
> > LPAE and non-LPAE setups.
> >
> > The KASan core code unconditionally calls pud_populate() so this
> > needs to be changed from BUG() to do {} while (0) when building
> > with KASan enabled.
> >
> > After the initial development by Andre Ryabinin several modifications
> > have been made to this code:
> >
> > Abbott Liu <liuwenliang@huawei.com>
> > - Add support ARM LPAE: If LPAE is enabled, KASan shadow region's
> >   mapping table need be copied in the pgd_alloc() function.
> > - Change kasan_pte_populate,kasan_pmd_populate,kasan_pud_populate,
> >   kasan_pgd_populate from .meminit.text section to .init.text section.
> >   Reported by Florian Fainelli <f.fainelli@gmail.com>
> >
> > Linus Walleij <linus.walleij@linaro.org>:
> > - Drop the custom mainpulation of TTBR0 and just use
> >   cpu_switch_mm() to switch the pgd table.
> > - Adopt to handle 4th level page tabel folding.
> > - Rewrite the entire page directory and page entry initialization
> >   sequence to be recursive based on ARM64:s kasan_init.c.
> >
> > Ard Biesheuvel <ardb@kernel.org>:
> > - Necessary underlying fixes.
> > - Crucial bug fixes to the memory set-up code.
> >
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: kasan-dev@googlegroups.com
> > Cc: Mike Rapoport <rppt@linux.ibm.com>
> > Co-developed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Co-developed-by: Abbott Liu <liuwenliang@huawei.com>
> > Co-developed-by: Ard Biesheuvel <ardb@kernel.org>
> > Acked-by: Mike Rapoport <rppt@linux.ibm.com>
> > Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
> > Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
> > Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
> > Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
> > Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
> > Reported-by: Florian Fainelli <f.fainelli@gmail.com>
> > Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> > Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> > Signed-off-by: Ard Biesheuvel <ardb@kernel.org>
> > Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> > ---
>
> ...
>
> > +     cpu_switch_mm(tmp_pgd_table, &init_mm);
> > +     local_flush_tlb_all();
> > +
> > +     clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
> > +
> > +     kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> > +                                 kasan_mem_to_shadow((void *)-1UL) + 1);
> > +
> > +     for_each_memblock(memory, reg) {
> > +             void *start = __va(reg->base);
> > +             void *end = __va(reg->base + reg->size);
> > +
>
> I've killed for_each_memblock() recently and we have now
>
>         for_each_mem_range(idx, &pa_start, &pa_end)
>
> instead.
>

Will the enumeration include NOMAP regions as well? We could actually
omit them here, since they don't need KASAN shadow.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGgrtj79UQ7Ei5NEEQ1_ALTJRVALFnjOmhZLb_4tSHauQ%40mail.gmail.com.
