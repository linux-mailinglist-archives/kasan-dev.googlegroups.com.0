Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBCHIUSHQMGQEZXVQR6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FDDE494B54
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jan 2022 11:06:01 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id c8-20020a05640227c800b003fdc1684cdesf5446224ede.12
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jan 2022 02:06:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642673161; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iq2xiQO6w0MGfJlf5MiMI/804/89uxx1Z8X1epHo5oayik/T3HoXe62ZerMIcpyP5+
         IfpjwVZR1tLAWy59Hn+wXGxG4hFv4njbMYXbc/JMZvo0oSMbE6yUgDgA3HO6+l8eES2b
         /bCY8nPDBFBFQRUSZ3vkQa7q4zfSAoUO2A+7U96+h3CwXdikaVxFoe3bS1dwGSam3pcp
         9Gik4GpCjT9VbjDivA+BBF5DjAeXkLTnQ+4q+M6ofosB4n3FVuTyJYdQU0uCRHFZDLe6
         sXAqbIpOYgJkvhrGvxMJwz8+6ZDmtoZlbOVGM1rMATCVxi1m24NViGKKIzx38+yhaeLB
         LsOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=paUhfilX0aHecBPdcrkqNPgo8CxiWIMP+1ZHj82Og98=;
        b=xD+mtNHxjALabduJikQuAlsPXqrF1+5qRJV6PGMb4pFLLbdDFgN/Oqw5zZzrEaMGz9
         lcgdzXa/ItlTZabisaDX1ylDxqzHJ3H5GYS7FVMIZHvOCqChia+VPHkUm1uzYL+R1rR+
         rgFLBBISJx5dXIPcVDIIX6PCxLiNkWeZ65XWJ/YUGZGrvsxct1xa4+g+fhGEDO1btV/W
         OSpvRenAidvWE3+EZdG/hZ7HCnbACQawkrEZZ2aCcgprFoT/SjcQfJ8N3We3ZlL6bcgb
         /8UTmFErJmWw/cBP4Qea9rgauIcGIgu6RNWQaUU0wCdBhfn1zsDrF1/hl3B7Ieok5zIk
         Omkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=VNMt+JsW;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=paUhfilX0aHecBPdcrkqNPgo8CxiWIMP+1ZHj82Og98=;
        b=dzY/1cnAAZWpWsLXzAaCW7FzCaJIFgvW/zLfgFnNGIcfnAZnPsdDWqfEi4UetFyhEw
         232pwQmzH4CA69VRWrEo8OXSr44xPZjhULbbdA64S3dsXCTVvICsD67+0ixlbE8NhoYH
         /uvAWdjlR2L69/KhWTbj8eO/Kdnkor+dPupkpw4LtqNjACJy/1CsL9E+ZPNTGN/6jfDE
         Rx+0xztY9629mZUnuz0UGS3sbS3CcxHhk+QwT93SPUOqITnou7EczqIT/Tmn6i4H1Qrh
         DVrVy/MLw/s+o1rwGI/r85GfqqMNA7nWbGb+wLtvDMrXuQAShI+tjFtVkbsZ66umgbvS
         Uz9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=paUhfilX0aHecBPdcrkqNPgo8CxiWIMP+1ZHj82Og98=;
        b=w4vwApBNv02FE+9NTBBCLzUt4UpJzYlz60E1vhe9M3bJ5r6tw2uCTT0HA6GQlPPJPJ
         8dmBB2+gAp3RduvBEfrXBQsKt8Fe1fM7R59YTBfAYFXRK4HmcZTh+Nfclxiu5I6X4Xga
         rH3nCndida73lQ+3B02/51chBnNZjp0eddohJ3seLOVQJraJIblKCGjKzzFDVZJaa2XL
         U9pjZvcDO5t2YVs37raxPVfQ0Xz5WJlhoa7eumgO7BYaFHJL7Ttgchg7OCGykoJEWp/q
         ev1xw/eQ0cNAaHtBDKSYq3g2MnYoYlvBZB2AQF5XhHw8fPJ+m4JKYW1fCLoswnh1zIGR
         FVXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302y9FUOXf9qgtuih20ukfp+jjMGiKxTjmL+8Em03XJTggc79Uo
	PhQM/bP7SKDr2+SLcnYBExc=
X-Google-Smtp-Source: ABdhPJwQnxSvA6VOO+boZNEQAHkXKDcT8if+34O1zw+Kq82gq7+qo1ChnEDsW6LPf9eKv5DLaIPnQQ==
X-Received: by 2002:a05:6402:1008:: with SMTP id c8mr35853521edu.114.1642673160790;
        Thu, 20 Jan 2022 02:06:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:94d4:: with SMTP id dn20ls2041863ejc.0.gmail; Thu,
 20 Jan 2022 02:05:59 -0800 (PST)
X-Received: by 2002:a17:906:a42:: with SMTP id x2mr30163966ejf.125.1642673159263;
        Thu, 20 Jan 2022 02:05:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642673159; cv=none;
        d=google.com; s=arc-20160816;
        b=vA/HBglr0PUQ2fME5Jzhd6Ck0uw2ugNhnw5xBG2lSUcQt9OYwNaS7PIRh/YUcRRE//
         sixTmIVk9rkNE2UZKZwxWbr7EiMX+ucj8qhYOXXFwblwxrmIm0KHU1QmvfoH3GVgg0lG
         xkcJ2QYXDJyJ+M8sE3skEKKubSq2uFSqbaf2HXEycLegFOfBu2KeGcSi7kozA0dpcoir
         UzMyqx6Qc6aLHFon4GfpuAUoraQj/17euBPrC5FzmxwxVoPgrVveBcJR7c3lBiPUXbut
         +/pdQ8HujmnAYgLlecCrluUVEhWx5jqEljN59BR+39wVF6rND+WhhKul7eDQvHGWj7wG
         orig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w26SyRlRb1I1H6K/gmJqzdX3K4fWh5zNRWtuBCu0Vhg=;
        b=IHxwUIxbnBivp9PZK+/HuFVrPvxKr5piKNeLnTe1nobNvXNSoTWK/QWKXYgOnG45AE
         0a/NHwgE5Q9mzgUUqFvm8s5KQTyWqdAf+D4WU9xa7Yrvt8Oye3gAI2CwgzoDBNfS5lRt
         57tIjTt5FwE/ChVnZnznOlBmZJ12lg3vEkRE6z4KLJ0PXDicJNL5T1n43PFNKiHvcOsY
         81Ew3BXqatFWWdeOi3nJSCFH3qFUQU/GTPG0xQZvLG4bKN9ZHQPmJ2PGQEn4N7B2YMLs
         XHydn36ZT3oYELlcs4AaQVRPB657xFZWMrYB3X/QKekdx3nz+fVscPtj5sKXhGio6Zr9
         OvpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=VNMt+JsW;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id h3si84369ede.4.2022.01.20.02.05.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Jan 2022 02:05:59 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 0211740028
	for <kasan-dev@googlegroups.com>; Thu, 20 Jan 2022 10:05:58 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id c11-20020a056402120b00b0040321cea9d4so5413183edw.23
        for <kasan-dev@googlegroups.com>; Thu, 20 Jan 2022 02:05:58 -0800 (PST)
X-Received: by 2002:a05:6402:b33:: with SMTP id bo19mr7643843edb.70.1642673157481;
        Thu, 20 Jan 2022 02:05:57 -0800 (PST)
X-Received: by 2002:a05:6402:b33:: with SMTP id bo19mr7643811edb.70.1642673157166;
 Thu, 20 Jan 2022 02:05:57 -0800 (PST)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <mhng-cdec292e-aea2-4b76-8853-b8465521e94f@palmer-ri-x1c9> <CA+zEjCuTSjOCmNExSN1jO50tsuXNzL9x6K6jWjG4+vVky5eWsw@mail.gmail.com>
In-Reply-To: <CA+zEjCuTSjOCmNExSN1jO50tsuXNzL9x6K6jWjG4+vVky5eWsw@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 20 Jan 2022 11:05:46 +0100
Message-ID: <CA+zEjCuTYmk-dLPhJ=9CkNrqf7VbCNyRDSZUGYkJSUWqZDWHpA@mail.gmail.com>
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
 header.i=@canonical.com header.s=20210705 header.b=VNMt+JsW;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

On Thu, Jan 20, 2022 at 8:30 AM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> On Thu, Jan 20, 2022 at 5:18 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> >
> > On Mon, 06 Dec 2021 02:46:44 PST (-0800), alexandre.ghiti@canonical.com wrote:
> > > * Please note notable changes in memory layouts and kasan population *
> > >
> > > This patchset allows to have a single kernel for sv39 and sv48 without
> > > being relocatable.
> > >
> > > The idea comes from Arnd Bergmann who suggested to do the same as x86,
> > > that is mapping the kernel to the end of the address space, which allows
> > > the kernel to be linked at the same address for both sv39 and sv48 and
> > > then does not require to be relocated at runtime.
> > >
> > > This implements sv48 support at runtime. The kernel will try to
> > > boot with 4-level page table and will fallback to 3-level if the HW does not
> > > support it. Folding the 4th level into a 3-level page table has almost no
> > > cost at runtime.
> > >
> > > Note that kasan region had to be moved to the end of the address space
> > > since its location must be known at compile-time and then be valid for
> > > both sv39 and sv48 (and sv57 that is coming).
> > >
> > > Tested on:
> > >   - qemu rv64 sv39: OK
> > >   - qemu rv64 sv48: OK
> > >   - qemu rv64 sv39 + kasan: OK
> > >   - qemu rv64 sv48 + kasan: OK
> > >   - qemu rv32: OK
> > >
> > > Changes in v3:
> > >   - Fix SZ_1T, thanks to Atish
> > >   - Fix warning create_pud_mapping, thanks to Atish
> > >   - Fix k210 nommu build, thanks to Atish
> > >   - Fix wrong rebase as noted by Samuel
> > >   - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
> > >   - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
> > >
> > > Changes in v2:
> > >   - Rebase onto for-next
> > >   - Fix KASAN
> > >   - Fix stack canary
> > >   - Get completely rid of MAXPHYSMEM configs
> > >   - Add documentation
> > >
> > > Alexandre Ghiti (13):
> > >   riscv: Move KASAN mapping next to the kernel mapping
> > >   riscv: Split early kasan mapping to prepare sv48 introduction
> > >   riscv: Introduce functions to switch pt_ops
> > >   riscv: Allow to dynamically define VA_BITS
> > >   riscv: Get rid of MAXPHYSMEM configs
> > >   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
> > >   riscv: Implement sv48 support
> > >   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
> > >   riscv: Explicit comment about user virtual address space size
> > >   riscv: Improve virtual kernel memory layout dump
> > >   Documentation: riscv: Add sv48 description to VM layout
> > >   riscv: Initialize thread pointer before calling C functions
> > >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
> > >
> > >  Documentation/riscv/vm-layout.rst             |  48 ++-
> > >  arch/riscv/Kconfig                            |  37 +-
> > >  arch/riscv/configs/nommu_k210_defconfig       |   1 -
> > >  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
> > >  arch/riscv/configs/nommu_virt_defconfig       |   1 -
> > >  arch/riscv/include/asm/csr.h                  |   3 +-
> > >  arch/riscv/include/asm/fixmap.h               |   1
> > >  arch/riscv/include/asm/kasan.h                |  11 +-
> > >  arch/riscv/include/asm/page.h                 |  20 +-
> > >  arch/riscv/include/asm/pgalloc.h              |  40 ++
> > >  arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
> > >  arch/riscv/include/asm/pgtable.h              |  47 +-
> > >  arch/riscv/include/asm/sparsemem.h            |   6 +-
> > >  arch/riscv/kernel/cpu.c                       |  23 +-
> > >  arch/riscv/kernel/head.S                      |   4 +-
> > >  arch/riscv/mm/context.c                       |   4 +-
> > >  arch/riscv/mm/init.c                          | 408 ++++++++++++++----
> > >  arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
> > >  drivers/firmware/efi/libstub/efi-stub.c       |   2
> > >  drivers/pci/controller/pci-xgene.c            |   2 +-
> > >  include/asm-generic/pgalloc.h                 |  24 +-
> > >  include/linux/sizes.h                         |   1
> > >  22 files changed, 833 insertions(+), 209 deletions(-)
> >
> > Sorry this took a while.  This is on for-next, with a bit of juggling: a
> > handful of trivial fixes for configs that were failing to build/boot and
> > some merge issues.  I also pulled out that MAXPHYSMEM fix to the top, so
> > it'd be easier to backport.  This is bigger than something I'd normally like to
> > take late in the cycle, but given there's a lot of cleanups, likely some fixes,
> > and it looks like folks have been testing this I'm just going to go with it.
> >
>
> Yes yes yes! That's fantastic news :)
>
> > Let me know if there's any issues with the merge, it was a bit hairy.
> > Probably best to just send along a fixup patch at this point.
>
> I'm going to take a look at that now, and I'll fix anything that comes
> up quickly :)

I see in for-next that you did not take the following patches:

  riscv: Improve virtual kernel memory layout dump
  Documentation: riscv: Add sv48 description to VM layout
  riscv: Initialize thread pointer before calling C functions
  riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN

I'm not sure this was your intention. If it was, I believe that at
least the first 2 patches are needed in this series, the 3rd one is a
useful fix and we can discuss the 4th if that's an issue for you.

I tested for-next on both sv39 and sv48 successfully, I took a glance
at the code and noticed you fixed the PTRS_PER_PGD error, thanks for
that. Otherwise nothing obvious has popped.

Thanks again,

Alex

>
> Thanks!
>
> Alex
>
> >
> > Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuTYmk-dLPhJ%3D9CkNrqf7VbCNyRDSZUGYkJSUWqZDWHpA%40mail.gmail.com.
