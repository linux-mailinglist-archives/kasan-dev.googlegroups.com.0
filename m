Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBMM7USHQMGQEA435X4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 909A3494846
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jan 2022 08:30:58 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id v13-20020ac25b0d000000b0043455bd1cbcsf834773lfn.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jan 2022 23:30:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642663858; cv=pass;
        d=google.com; s=arc-20160816;
        b=pOjDHbyOEFFrr6f2knZ8jwtoEMdvuMeTXpeupPxIu12aVP7thwWVkzYFsP4AsIQ/yg
         bkbFLetGHtkjb+3UUWQJO7HIrWGcYGiiboQu4vd2xmu2P0nyoWbN78ZtJs/b84GnXGwT
         0cOCfNa5J3BWikSA6VJ3SioaVSeQd09GRLLC91tNz8ToXRUMjHHrSAoVIOU9R6pOZOFN
         IsvR9LiK5W4m4wey+6Ud5dlA2CiH8B0rv6r5FBXioDJjj17c0oUmfPNcK8PHTYQmo41G
         fXPmSoSuHnkBPfFYbIKaFXPhUThpFBq7S5pp99hQv6CvzLaYpZcp+SA+JXaC+mZ2ud6K
         U3Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=oIXCJOkiWe6p/zWdQhndm7PT/S96VjRA/X+BaBjjSUI=;
        b=Zq2aQHu9qjO0KidtnkBIaL2uGv6pkxjP9FxXsuSVIjVFTdWKSDFPNhxExcrrTOyv0t
         S2EsmlE0JoYrHWon5wlgYIMGpb3cwUq/82X5yAxzwoH7D746aDo59z3+ghOkT25RKbxh
         326wheW/OjD4AyUoXgFH8nuCXX04QK8AyN6PIja4uHEmevjN9WaAWlfjQlfh2ATElBJl
         x0iU10KvMsIMcGvXAmexim9sUmwA6hQm51cSyc2RcdNdL9ILITjS9Y2LJGdGVqNM+fZf
         AIDJR/WwbwoV2I0vffYcGoKS/xSek6eqmhRuQGS2MULG2eTLV4AKrFRz+XcOU12mQfcM
         EcFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=H0DpcxNd;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oIXCJOkiWe6p/zWdQhndm7PT/S96VjRA/X+BaBjjSUI=;
        b=TXWbq0z4cZ78hrsBRa3VwGEobDoAyw/XMlumvP19+2kU2GJ5mp3IX56ECIhdJogJ+v
         i4SLp6ornHlKf+nxy/t2wVygcW0HsPN0i0fflTYVUKrOsfrF/YrQARB5QEfUM7laIsXe
         lQt0h717e1AXkBN46hpZzBbTyQC7dZBhckOjhE1jNJhL0kcXEy8iRzjnQqnTvT4WdH3r
         Y6CLCBgs117mSZGZ2BkxtVrsQbSFXeISIj7a180JjF7JhsomRUTSrxQbgGMlRnlGySxF
         MYdMAst1P9iHG6R4Cuu6no9v8pMA8qaYx7GDf9CVfvFfQtgm536b8hpYamll6QyPQ32e
         KLuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oIXCJOkiWe6p/zWdQhndm7PT/S96VjRA/X+BaBjjSUI=;
        b=c1++c+3VkGf2dg8ysAM61x5HaKP4LQI0FXcdzMdE0LBZchIIhL2I8uhOF7nnTLCclx
         A/xd+ULP1VK1eaVj5LSJrqCVKbmZMQcyiO5dI4JslQ9oxwMv6aaqsLiWZx3FWY2iNIaw
         psr7Da1LMY0Uj2l1lH9rppSMhPEYvmPZ1r6FyC8WbmXbjpx5K9MF7CNgV1FJZmHBXIPC
         rqo9yeehbLpC1000QHfdTyHypfOHKsOrI4NY0yVdzhFUge9oRvpDE/x6yhFQbOhUMQEZ
         O98lpzrp/E48mdWXZL49Dy4XeNpn7feLo+l5yqJ3Kp9cszmaOqR5yUtxWpJ9g6n8KBJ9
         uIrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TKYhzwjdZb3hmq+i8w45kTlTrEOBl+X6Y/VxH1REOtiDUNtHz
	UZLJMSB0dOkSWNc2m9b3XlI=
X-Google-Smtp-Source: ABdhPJyHuJaFUlHGx/HHnjZeRO3vE6ofz7wCt7hqRK41wxTi2FhcbIdVG2+px0KoMOXtgnHUZNxigQ==
X-Received: by 2002:ac2:57c7:: with SMTP id k7mr32162804lfo.110.1642663857980;
        Wed, 19 Jan 2022 23:30:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a550:: with SMTP id e16ls717869ljn.11.gmail; Wed, 19 Jan
 2022 23:30:57 -0800 (PST)
X-Received: by 2002:a2e:a26d:: with SMTP id k13mr14237431ljm.300.1642663856977;
        Wed, 19 Jan 2022 23:30:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642663856; cv=none;
        d=google.com; s=arc-20160816;
        b=LoUVxPPl7vdnv1CM+kPYlF5TNYy7Erw0CIHxj36+CbrgydVgHscEhFw3BMwRsdrUU5
         Q1JqRNOTOrwcn9Yz8zJ4umqa/Vhpmnab62k61ZSX6jz+Aks5rPSuj5TLHhqQNlv4cCvs
         jTYXOqpTMWcR9wqr3Kcnkq+Dj31EcFe1AaXc0e87FdAmLvW4levVX1fN6cyd2WU7JEqM
         +/ExobPczUBSxYz9yz2et5ItBN67SI/hL8xcwhGQWttwyxxpy4V6lBgu7q/Rq1eHuD2B
         z06jRFElihSKRfLwHM+dulG9RC5SOgkTd3a05sCgCTWRU54j0Ge4dxolRq7r17rf3tBT
         HwjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dCQXkZtZ/VwDrAN2uVWBP6tsU2v5k0SPHuefqy0UyIg=;
        b=NZFlPzWbhmOIifO1qgPOsv0Y4QE/D2hzkKQXxQw+xmrhCnn3kHGaC2FPFyrtR11djK
         2vqfXLsrEMPuUzYRxqmd2yJSon0TE50oD8GSTFtlzCWLPDH5C7Qv3nPHPywMTAVavBpV
         NuAkHILLWYpxIhLcKhKkWcVfluLGezLEI7vjvLX1SvF7r4rn/JkRCMyLfkF7zNwwZH1G
         cGYvlsB0ALkXN3a5OlHsfAph6j2jsIb7seAXIbnLWwQDLtrtJWOqmOaV2yJ5oZX5a9iz
         78RcvzDrlKXH4nb8PIMXFWeIoDemZUUtjfxNkyxV0wZ0DUnTJ7OQC51MMMR64L0YOYTa
         dQRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=H0DpcxNd;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id z20si62289ljj.5.2022.01.19.23.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jan 2022 23:30:56 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id E3CC13F1E9
	for <kasan-dev@googlegroups.com>; Thu, 20 Jan 2022 07:30:55 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id k10-20020a50cb8a000000b00403c8326f2aso5089134edi.6
        for <kasan-dev@googlegroups.com>; Wed, 19 Jan 2022 23:30:55 -0800 (PST)
X-Received: by 2002:a05:6402:268a:: with SMTP id w10mr35311108edd.10.1642663855555;
        Wed, 19 Jan 2022 23:30:55 -0800 (PST)
X-Received: by 2002:a05:6402:268a:: with SMTP id w10mr35311082edd.10.1642663855317;
 Wed, 19 Jan 2022 23:30:55 -0800 (PST)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com> <mhng-cdec292e-aea2-4b76-8853-b8465521e94f@palmer-ri-x1c9>
In-Reply-To: <mhng-cdec292e-aea2-4b76-8853-b8465521e94f@palmer-ri-x1c9>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 20 Jan 2022 08:30:43 +0100
Message-ID: <CA+zEjCuTSjOCmNExSN1jO50tsuXNzL9x6K6jWjG4+vVky5eWsw@mail.gmail.com>
Subject: Re: [PATCH v3 00/13] Introduce sv48 support without relocatable kernel
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, 
	zong.li@sifive.com, anup@brainfault.org, Atish.Patra@rivosinc.com, 
	Christoph Hellwig <hch@lst.de>, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, ardb@kernel.org, 
	Arnd Bergmann <arnd@arndb.de>, keescook@chromium.org, guoren@linux.alibaba.com, 
	heinrich.schuchardt@canonical.com, mchitale@ventanamicro.com, 
	panqinglin2020@iscas.ac.cn, linux-doc@vger.kernel.org, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=H0DpcxNd;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Thu, Jan 20, 2022 at 5:18 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>
> On Mon, 06 Dec 2021 02:46:44 PST (-0800), alexandre.ghiti@canonical.com wrote:
> > * Please note notable changes in memory layouts and kasan population *
> >
> > This patchset allows to have a single kernel for sv39 and sv48 without
> > being relocatable.
> >
> > The idea comes from Arnd Bergmann who suggested to do the same as x86,
> > that is mapping the kernel to the end of the address space, which allows
> > the kernel to be linked at the same address for both sv39 and sv48 and
> > then does not require to be relocated at runtime.
> >
> > This implements sv48 support at runtime. The kernel will try to
> > boot with 4-level page table and will fallback to 3-level if the HW does not
> > support it. Folding the 4th level into a 3-level page table has almost no
> > cost at runtime.
> >
> > Note that kasan region had to be moved to the end of the address space
> > since its location must be known at compile-time and then be valid for
> > both sv39 and sv48 (and sv57 that is coming).
> >
> > Tested on:
> >   - qemu rv64 sv39: OK
> >   - qemu rv64 sv48: OK
> >   - qemu rv64 sv39 + kasan: OK
> >   - qemu rv64 sv48 + kasan: OK
> >   - qemu rv32: OK
> >
> > Changes in v3:
> >   - Fix SZ_1T, thanks to Atish
> >   - Fix warning create_pud_mapping, thanks to Atish
> >   - Fix k210 nommu build, thanks to Atish
> >   - Fix wrong rebase as noted by Samuel
> >   - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
> >   - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
> >
> > Changes in v2:
> >   - Rebase onto for-next
> >   - Fix KASAN
> >   - Fix stack canary
> >   - Get completely rid of MAXPHYSMEM configs
> >   - Add documentation
> >
> > Alexandre Ghiti (13):
> >   riscv: Move KASAN mapping next to the kernel mapping
> >   riscv: Split early kasan mapping to prepare sv48 introduction
> >   riscv: Introduce functions to switch pt_ops
> >   riscv: Allow to dynamically define VA_BITS
> >   riscv: Get rid of MAXPHYSMEM configs
> >   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
> >   riscv: Implement sv48 support
> >   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
> >   riscv: Explicit comment about user virtual address space size
> >   riscv: Improve virtual kernel memory layout dump
> >   Documentation: riscv: Add sv48 description to VM layout
> >   riscv: Initialize thread pointer before calling C functions
> >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
> >
> >  Documentation/riscv/vm-layout.rst             |  48 ++-
> >  arch/riscv/Kconfig                            |  37 +-
> >  arch/riscv/configs/nommu_k210_defconfig       |   1 -
> >  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
> >  arch/riscv/configs/nommu_virt_defconfig       |   1 -
> >  arch/riscv/include/asm/csr.h                  |   3 +-
> >  arch/riscv/include/asm/fixmap.h               |   1
> >  arch/riscv/include/asm/kasan.h                |  11 +-
> >  arch/riscv/include/asm/page.h                 |  20 +-
> >  arch/riscv/include/asm/pgalloc.h              |  40 ++
> >  arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
> >  arch/riscv/include/asm/pgtable.h              |  47 +-
> >  arch/riscv/include/asm/sparsemem.h            |   6 +-
> >  arch/riscv/kernel/cpu.c                       |  23 +-
> >  arch/riscv/kernel/head.S                      |   4 +-
> >  arch/riscv/mm/context.c                       |   4 +-
> >  arch/riscv/mm/init.c                          | 408 ++++++++++++++----
> >  arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
> >  drivers/firmware/efi/libstub/efi-stub.c       |   2
> >  drivers/pci/controller/pci-xgene.c            |   2 +-
> >  include/asm-generic/pgalloc.h                 |  24 +-
> >  include/linux/sizes.h                         |   1
> >  22 files changed, 833 insertions(+), 209 deletions(-)
>
> Sorry this took a while.  This is on for-next, with a bit of juggling: a
> handful of trivial fixes for configs that were failing to build/boot and
> some merge issues.  I also pulled out that MAXPHYSMEM fix to the top, so
> it'd be easier to backport.  This is bigger than something I'd normally like to
> take late in the cycle, but given there's a lot of cleanups, likely some fixes,
> and it looks like folks have been testing this I'm just going to go with it.
>

Yes yes yes! That's fantastic news :)

> Let me know if there's any issues with the merge, it was a bit hairy.
> Probably best to just send along a fixup patch at this point.

I'm going to take a look at that now, and I'll fix anything that comes
up quickly :)

Thanks!

Alex

>
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuTSjOCmNExSN1jO50tsuXNzL9x6K6jWjG4%2BvVky5eWsw%40mail.gmail.com.
