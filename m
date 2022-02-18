Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB27RXWIAMGQE5W3H3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A88B4BB729
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 11:46:04 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id v13-20020ac2592d000000b004435f5315dbsf570124lfi.21
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 02:46:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645181163; cv=pass;
        d=google.com; s=arc-20160816;
        b=VAeWOZ6nOnhDqv4UCDeosWNEGAKxE2C0MwwlQuYokZmTsLlmiW6k/O2B12G6jJGWmp
         AVzGGkvNLaqQ+s0brXsrB4N2zo5MHvmgy8of/idc4ep58N9Ugqw6cASshDhrXeXxRXeA
         V80mS5UOkeXmjbE9KPR0f84eCXUbNGUWSjkzOxjS5o0QzPO/p1s/vt7vUUNXHUGo5RSj
         Wi3KiqTs2SM6rlOzi2+JIz1s5jH6azgIO69oDbOOKEN2kWymOIj+ulavf5Iz4/4Gh7yv
         bcs3nYwcjIonvkE548rlbJwOLYrgf1qs4NuikL4BAtbzmg23eRPxfbun7RKh/5oH1EuP
         8y7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=9LWPqsIg+9AsU+UV3OIqp3tQhqAbrhljv/49P7C8I6g=;
        b=fYbddBNLz8q8L+HnUkycvfrk2QS/JTMzLoWDusuhJ4mm/JuWz+DelhHlrnPtSpRC5c
         w/hsORoJC5vweorTuo52BKAUh0+90kr4t9MPr5zj728Ug530iC3827CshiLRZAG0lo4M
         1a4TVN2vjQwFRyOkxbzvOr4FVNRGlVB83Bwg+oAyIdwJ+aTiHl+jx3v9hI5K4U+MmV3O
         QS29yf7b00A6P98yIvdciuN/8P6ZlhL2/43NLG2GqP7cmLR64euc3e3vEggu29JRd/ys
         YByyhHBAHTqAcT4vG1UrjguNykj4UXveTWf6IJYX3Hs2Xhm/H3qHNHd86rYNCEut2Bdp
         bRKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=MnbNQWNh;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9LWPqsIg+9AsU+UV3OIqp3tQhqAbrhljv/49P7C8I6g=;
        b=erxFK/585rzmmfGHjA2YSuiP9tzV68Sk33iq9Dc9dpTI9EA3INO/SWWgGWIV7JQUnP
         EnH5zwi2LUpVoDGf7ynwwG8EDXMt6w/ycQRUelCIoXjlsCFiZwWAJZsAmK1qX5bbsQmQ
         w4P6a7L4LvU83EpCH/3H2NjCaRAoYmX5HDv4ONgLuwOqpl/0kFl2ka450bwbG0wqtD7m
         kKJt2dOa/7lxmme0tgN0SA6vk/DRhJh+ZJWv2ZvkTTv5ceuHiRmgPEurBsdC6zYoC0WR
         OwMV5XVFADpGVScOd7KnMlEWMR8UZkNy2UOoC+zswzwpwHLCdFXgyQ+gKkxinILWnxQE
         i1LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9LWPqsIg+9AsU+UV3OIqp3tQhqAbrhljv/49P7C8I6g=;
        b=WRiaBi8WG4fIAr3txUEO3TU4Y3kLZ84F4b4E4fs0FaLiP/sd8tVDj0DuyK0nqn+1fb
         2fqXyfsEpMlFCcWrHepwmAeznh8a46jzj91XuExyS7xq8vyy/jkl4OkZgTL9+wtUJ2n5
         iYIolA7yoaaNO9BeB2fUADObxHJEfRD/Kza4e06ZE9zLpNOVDb1L1RZB92lhuDaP2IW3
         7xNeLFFTRDgSVAjTynR9/9nMOhAh87UqT66rLY9646wNkPKFurydK9dQn6ltm4N5o18K
         rf1QX3p2xBFSRhewcOEIiADF9Vjg8ZAiFfVdTeVlFvQ8+IcBS47Bs2UHlF7Ze+5V7nE1
         S+Vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Tgm/Ui2LQLo/kpxkX/w3G73cAxUdgT/MOySIfIMqgiZQjX+LQ
	DzBALEMIGqVf12iBTMb61z8=
X-Google-Smtp-Source: ABdhPJx0tee+x5pTMbTwhhwRXNTMaB62GlmHKXhm24bnt4FyA0L3x0TK0EaA/sSSWLzym9xzAYZpTg==
X-Received: by 2002:a05:651c:14f:b0:246:e2c:a985 with SMTP id c15-20020a05651c014f00b002460e2ca985mr5357836ljd.122.1645181163416;
        Fri, 18 Feb 2022 02:46:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a3:b0:443:7b15:f451 with SMTP id
 bp35-20020a05651215a300b004437b15f451ls731799lfb.0.gmail; Fri, 18 Feb 2022
 02:46:02 -0800 (PST)
X-Received: by 2002:a05:6512:21b2:b0:43b:5b66:8e76 with SMTP id c18-20020a05651221b200b0043b5b668e76mr5027527lft.327.1645181162381;
        Fri, 18 Feb 2022 02:46:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645181162; cv=none;
        d=google.com; s=arc-20160816;
        b=w0QjK25EVmM9iEcdrxVTk7cEQF2hFeeRfc63QQr5N4cG2vGEb6ytUpdnoy3EPcwoR1
         LtDIQ3dDk9pO7yN15oXW3zV4mwCB2Bu/s1ezHRTpBWoLUTBABGOTeQ2ex2ldpYQus0Fk
         P6Wc1nIiuGgqKr8oh98SFQH4wk23+B0I0Be8hIXNEyGVlt5QoNDYVXEcqVbeLGfmjp2w
         Dt2rfbr7neR/dw9fytdfrv/GyfSLuBCWCoQPIEa1LUxCJgQt43UV46cNegRmNzeUS+uA
         kq/3XsOps1jQKqcXv4XyLrHT4Yo27YxJV2DRzgDyKOZGw6f3yTVPoGRqaRxK1LbpfaV3
         XUvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dGDRz61XRlmN2nrsI5bz0i1S0S+h5+fQGdDwmq0wB0k=;
        b=nE6l/TBzZYqcFmVMYkS3OUsei/Nx+boAZZF7vhOeUcmE+3SaJgCAiUCdMh0UBWroD6
         Zu/FH1GRWbraSlSv/Oj4IE8oXuBOdArvEpyo7g+37V+pLfqwF0ZS3MfJgfonLHk4DPHK
         BCdp/iHC4asxtR5R6crNPMTuZxaWXCtMqjseQkEw1Go57ASjRlBeeKhbf3BNqtldXjZc
         ZB3KeiqEZ4sDrHWwrcc7AtvPQXYv0Kn6RaWux9kQzB0J4bqOq89iQpRU8f1/lGskOQb/
         lsVL9qpOA/RZ3Fd2akk9q/zYnHiRwm9gwbjlJdE4R1qKuRY6xuc0xJf5GFCjXWQCi3YS
         eglg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=MnbNQWNh;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id d35si106164lfv.5.2022.02.18.02.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 02:46:02 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 294E94029B
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 10:46:01 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id o8-20020a056402438800b00410b9609a62so5267442edc.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 02:46:01 -0800 (PST)
X-Received: by 2002:aa7:d3d9:0:b0:410:7a81:c0cf with SMTP id o25-20020aa7d3d9000000b004107a81c0cfmr7414116edr.177.1645181160597;
        Fri, 18 Feb 2022 02:46:00 -0800 (PST)
X-Received: by 2002:aa7:d3d9:0:b0:410:7a81:c0cf with SMTP id
 o25-20020aa7d3d9000000b004107a81c0cfmr7414090edr.177.1645181160350; Fri, 18
 Feb 2022 02:46:00 -0800 (PST)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <mhng-cdec292e-aea2-4b76-8853-b8465521e94f@palmer-ri-x1c9>
 <CA+zEjCuTSjOCmNExSN1jO50tsuXNzL9x6K6jWjG4+vVky5eWsw@mail.gmail.com> <CA+zEjCuTYmk-dLPhJ=9CkNrqf7VbCNyRDSZUGYkJSUWqZDWHpA@mail.gmail.com>
In-Reply-To: <CA+zEjCuTYmk-dLPhJ=9CkNrqf7VbCNyRDSZUGYkJSUWqZDWHpA@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Fri, 18 Feb 2022 11:45:49 +0100
Message-ID: <CA+zEjCt04OV++qK5ar+p8HwqOfEgkSN8YFfxwRiCFw1FeJv2rg@mail.gmail.com>
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
 header.i=@canonical.com header.s=20210705 header.b=MnbNQWNh;       spf=pass
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

Hi Palmer,

On Thu, Jan 20, 2022 at 11:05 AM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> On Thu, Jan 20, 2022 at 8:30 AM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > On Thu, Jan 20, 2022 at 5:18 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> > >
> > > On Mon, 06 Dec 2021 02:46:44 PST (-0800), alexandre.ghiti@canonical.com wrote:
> > > > * Please note notable changes in memory layouts and kasan population *
> > > >
> > > > This patchset allows to have a single kernel for sv39 and sv48 without
> > > > being relocatable.
> > > >
> > > > The idea comes from Arnd Bergmann who suggested to do the same as x86,
> > > > that is mapping the kernel to the end of the address space, which allows
> > > > the kernel to be linked at the same address for both sv39 and sv48 and
> > > > then does not require to be relocated at runtime.
> > > >
> > > > This implements sv48 support at runtime. The kernel will try to
> > > > boot with 4-level page table and will fallback to 3-level if the HW does not
> > > > support it. Folding the 4th level into a 3-level page table has almost no
> > > > cost at runtime.
> > > >
> > > > Note that kasan region had to be moved to the end of the address space
> > > > since its location must be known at compile-time and then be valid for
> > > > both sv39 and sv48 (and sv57 that is coming).
> > > >
> > > > Tested on:
> > > >   - qemu rv64 sv39: OK
> > > >   - qemu rv64 sv48: OK
> > > >   - qemu rv64 sv39 + kasan: OK
> > > >   - qemu rv64 sv48 + kasan: OK
> > > >   - qemu rv32: OK
> > > >
> > > > Changes in v3:
> > > >   - Fix SZ_1T, thanks to Atish
> > > >   - Fix warning create_pud_mapping, thanks to Atish
> > > >   - Fix k210 nommu build, thanks to Atish
> > > >   - Fix wrong rebase as noted by Samuel
> > > >   - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
> > > >   - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
> > > >
> > > > Changes in v2:
> > > >   - Rebase onto for-next
> > > >   - Fix KASAN
> > > >   - Fix stack canary
> > > >   - Get completely rid of MAXPHYSMEM configs
> > > >   - Add documentation
> > > >
> > > > Alexandre Ghiti (13):
> > > >   riscv: Move KASAN mapping next to the kernel mapping
> > > >   riscv: Split early kasan mapping to prepare sv48 introduction
> > > >   riscv: Introduce functions to switch pt_ops
> > > >   riscv: Allow to dynamically define VA_BITS
> > > >   riscv: Get rid of MAXPHYSMEM configs
> > > >   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
> > > >   riscv: Implement sv48 support
> > > >   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
> > > >   riscv: Explicit comment about user virtual address space size
> > > >   riscv: Improve virtual kernel memory layout dump
> > > >   Documentation: riscv: Add sv48 description to VM layout
> > > >   riscv: Initialize thread pointer before calling C functions
> > > >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
> > > >
> > > >  Documentation/riscv/vm-layout.rst             |  48 ++-
> > > >  arch/riscv/Kconfig                            |  37 +-
> > > >  arch/riscv/configs/nommu_k210_defconfig       |   1 -
> > > >  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
> > > >  arch/riscv/configs/nommu_virt_defconfig       |   1 -
> > > >  arch/riscv/include/asm/csr.h                  |   3 +-
> > > >  arch/riscv/include/asm/fixmap.h               |   1
> > > >  arch/riscv/include/asm/kasan.h                |  11 +-
> > > >  arch/riscv/include/asm/page.h                 |  20 +-
> > > >  arch/riscv/include/asm/pgalloc.h              |  40 ++
> > > >  arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
> > > >  arch/riscv/include/asm/pgtable.h              |  47 +-
> > > >  arch/riscv/include/asm/sparsemem.h            |   6 +-
> > > >  arch/riscv/kernel/cpu.c                       |  23 +-
> > > >  arch/riscv/kernel/head.S                      |   4 +-
> > > >  arch/riscv/mm/context.c                       |   4 +-
> > > >  arch/riscv/mm/init.c                          | 408 ++++++++++++++----
> > > >  arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
> > > >  drivers/firmware/efi/libstub/efi-stub.c       |   2
> > > >  drivers/pci/controller/pci-xgene.c            |   2 +-
> > > >  include/asm-generic/pgalloc.h                 |  24 +-
> > > >  include/linux/sizes.h                         |   1
> > > >  22 files changed, 833 insertions(+), 209 deletions(-)
> > >
> > > Sorry this took a while.  This is on for-next, with a bit of juggling: a
> > > handful of trivial fixes for configs that were failing to build/boot and
> > > some merge issues.  I also pulled out that MAXPHYSMEM fix to the top, so
> > > it'd be easier to backport.  This is bigger than something I'd normally like to
> > > take late in the cycle, but given there's a lot of cleanups, likely some fixes,
> > > and it looks like folks have been testing this I'm just going to go with it.
> > >
> >
> > Yes yes yes! That's fantastic news :)
> >
> > > Let me know if there's any issues with the merge, it was a bit hairy.
> > > Probably best to just send along a fixup patch at this point.
> >
> > I'm going to take a look at that now, and I'll fix anything that comes
> > up quickly :)
>
> I see in for-next that you did not take the following patches:
>
>   riscv: Improve virtual kernel memory layout dump
>   Documentation: riscv: Add sv48 description to VM layout
>   riscv: Initialize thread pointer before calling C functions
>   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
>
> I'm not sure this was your intention. If it was, I believe that at
> least the first 2 patches are needed in this series, the 3rd one is a
> useful fix and we can discuss the 4th if that's an issue for you.

Can you confirm that this was intentional and maybe explain the
motivation behind it? Because I see value in those patches.

Thanks,

Alex

>
> I tested for-next on both sv39 and sv48 successfully, I took a glance
> at the code and noticed you fixed the PTRS_PER_PGD error, thanks for
> that. Otherwise nothing obvious has popped.
>
> Thanks again,
>
> Alex
>
> >
> > Thanks!
> >
> > Alex
> >
> > >
> > > Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCt04OV%2B%2BqK5ar%2Bp8HwqOfEgkSN8YFfxwRiCFw1FeJv2rg%40mail.gmail.com.
