Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBDPNTOJAMGQELLBZ5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 09CB04EED8A
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 14:56:46 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id y23-20020a0565123f1700b00448221b91e5sf1182743lfa.13
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 05:56:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648817805; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWmq4p8gEwwywftoGwEkMZWj4Y//oRpgSE2EAsAo9YMkpkwJffxNkAZetDvDqsl0Y6
         ux5vnybMW2snQORSY3+UcXZYj3YLDC/nsmXQW8EwkdfzU+kgXm83qWnaayUSlZHP6piW
         ZJW21qU1BkfdWIcZZfsrLftjR9UwnPdpXntMsntQ9+aNXS84u5c+F121qRGucoxAMX5I
         EbKQ3q1wxQXyuQuAReLKjPpAic1TlY8tXQImvyXCMzY+VOfopsx/ARJg7GYNhQf9zqo1
         SuBQmwjSYvk/BAj1sWZe1QVo1/yJdvmqUqOLAbI0v9MiI+mFx/f1r5HONqZa07Fs9BWH
         iJ8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=1ucruqvnsc7oSLUNt1yDTgy+UDppkAt4Fhom5x6EM5Q=;
        b=UTdig0oTipm9iFh+AYen55uF6njKCHE/nWceCv5okNy1Cg92ifWOzJv+n/U9Rx63Vz
         jey+zF09UbLdNc1u+zp34W95yzu8/eDbLtKO8kM8BuUxdXGZ88QrDr06lXxeYhlEb8ci
         wcLiDvijSSW0t/jVM+bY5lKVYKtPFDHhK13fb0GYoekiJ5KpGsGZ0WHPvvH2WxuIIR3U
         LHGL0Zc+90NADeEyh47dAqoua8UYcfoCHenOB8IALzjveiAvNOWjM/U3q4LM1NECm1Au
         z11hgkbMqZ6X+g0rJYcTIfOJjsDV2AR1dkGPpQ9u3SP8OxIkCgE2H64ReAB0+Bek990d
         NXtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="mye6/+uv";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ucruqvnsc7oSLUNt1yDTgy+UDppkAt4Fhom5x6EM5Q=;
        b=WI2AvnwhfB1tk+4EVyLegvTU6vJWziG2Xn50+6MORk+LPIxncdX3BG0Bs8kH5Rw/i7
         zQkpzBNZpTf5GMieNsbs05OvY2OGULaHLtZGgBqXUeu/vUdXqOzc/SrpBQTFE5SRDfYr
         aR6QwtU9nKUO7nAOb0k9kwwW/z50l5WG3DXiHX9lyU+kwcrSjIpKwn2wHIak2++J2zkB
         Cp9gvB7uGLd3eTE5+r1eU39MaI9USC8gseIXPLKhbMJPXM0B/2gipNcCrPlqO5vCZJ+Q
         +ZsDYto71aj1pfbwz3egJHw/N28cFly7hj6+gvpQxXzQ5nNdkzYK5g2MOZvHUTX/xTKo
         8MpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ucruqvnsc7oSLUNt1yDTgy+UDppkAt4Fhom5x6EM5Q=;
        b=QtRVKzPy/RjoH0HjRp13DEA3EtttgdHqrb/l4l+VkzmSy4TFojVHE+IHPl6DYtNN1f
         pm7hAumwjDam63niMAYxD496Ij9U2pAeZxMW42SThofslOxiSlUYLKkO2FutK4q6ycTY
         suSuJvdx9Z6qDV6oIBmAfIKQn9Y5GiiZyaO90xf2H39eoIXuJyGexpPDYbXOqV5d9LdI
         /zRVlsAuIDixxznnzHufb9iAkSY0fd9WLnhOleLJsB0rRCIUTjzBP5I6PS55D+MQsxXq
         JMFVgkpAVT7I1Ya8PV0Y1Y3b4tR+8PjKKS+Cy66JSY10o6IsGTJp+X5guReR97a38F1L
         jHBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BjlXtDJg7LSco8x5xveT6xJdOe9QtHbfDHbeCHVdQrFy6q0QC
	b7jl6ggyKNWUqJYS07dKvrc=
X-Google-Smtp-Source: ABdhPJwEWkEa+hVX0AUwcXcH8VCUB4jkJG7CdB4BqVh7E7fMWCIAMFcRFlcQgWiSZ3pA+6Fvq93PHw==
X-Received: by 2002:a05:6512:b99:b0:44a:db34:de43 with SMTP id b25-20020a0565120b9900b0044adb34de43mr1911991lfv.371.1648817805440;
        Fri, 01 Apr 2022 05:56:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90ce:0:b0:249:7e33:4f9b with SMTP id o14-20020a2e90ce000000b002497e334f9bls353163ljg.0.gmail;
 Fri, 01 Apr 2022 05:56:44 -0700 (PDT)
X-Received: by 2002:a05:651c:311:b0:23f:d9fc:9e89 with SMTP id a17-20020a05651c031100b0023fd9fc9e89mr13420096ljp.136.1648817804385;
        Fri, 01 Apr 2022 05:56:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648817804; cv=none;
        d=google.com; s=arc-20160816;
        b=f14zH+t5eGQLaJGLvUYh52vp3Hrd2Aat4cplh32xwGXNiWG/f/n6LFV1kzzWYesh4J
         hlnnuUr0DWfw6FBlRlwBZy1C9CeMr7Pn9cecDhmGUCggYqRcDpQU9WI6YSWn25gaYuKg
         gZ9WeieMJgtI/kIAQjasdTqxUqV0aaZmF5yurfZqxI28nUBOMxy4M+mTjmX2Wix387mA
         A3nvvu4MLM+xffR/bp1x2zE5R6YENTowlmdyYMUYt+i0U54dlZE7kvNTu9DknJ51W7yb
         xrcZDXvwKxUeZml6W9l+iZs5hf7QMNoCGQl4/xTuNNXyYQrhxU9HplJZBhwl/IW7fzA3
         1FFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oz27duE5Ryo8jJ1fge3md1VX7PuJsZs6ffNWaIrGhqo=;
        b=Nwc7in0sovniK2ApyA9RsdwGu+8XQ8WSbYmafUYZglQTItcpk9D5Duqc4VBWi7TrFU
         mj1K9qvOlQkE4gZHM0EotYBIhG8RDKw5m11AkU22+6vBUulQ0EZ+XdoRnngycw2E5ExB
         WpChwgth0AEIjm6PBfeWneN8dm2nAEghPdyrkIQl3WwJWnvMwXuAdDVn8Q6L/sAyhJRJ
         QvvIYpYdipnniZlFE6EJbKpDPskk+T/efFEKUbG45dw6kn3v1fCoEZL0Z1tyHZh0UI5J
         k64j6xmLy83sM0EKZWcFIMRKv/9NMmtjAAwl+O83A5maw+aF0zogDArjEQe2NDu0T62m
         JZdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="mye6/+uv";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id x40-20020a0565123fa800b004487bb2d452si140670lfa.0.2022.04.01.05.56.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Apr 2022 05:56:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ej1-f69.google.com (mail-ej1-f69.google.com [209.85.218.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id B4DBA3F800
	for <kasan-dev@googlegroups.com>; Fri,  1 Apr 2022 12:56:42 +0000 (UTC)
Received: by mail-ej1-f69.google.com with SMTP id gt41-20020a1709072da900b006e490a92df4so1547555ejc.4
        for <kasan-dev@googlegroups.com>; Fri, 01 Apr 2022 05:56:42 -0700 (PDT)
X-Received: by 2002:a17:907:6d90:b0:6e4:de0d:462 with SMTP id sb16-20020a1709076d9000b006e4de0d0462mr1479985ejc.297.1648817802133;
        Fri, 01 Apr 2022 05:56:42 -0700 (PDT)
X-Received: by 2002:a17:907:6d90:b0:6e4:de0d:462 with SMTP id
 sb16-20020a1709076d9000b006e4de0d0462mr1479957ejc.297.1648817801897; Fri, 01
 Apr 2022 05:56:41 -0700 (PDT)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <mhng-cdec292e-aea2-4b76-8853-b8465521e94f@palmer-ri-x1c9>
 <CA+zEjCuTSjOCmNExSN1jO50tsuXNzL9x6K6jWjG4+vVky5eWsw@mail.gmail.com>
 <CA+zEjCuTYmk-dLPhJ=9CkNrqf7VbCNyRDSZUGYkJSUWqZDWHpA@mail.gmail.com> <CA+zEjCt04OV++qK5ar+p8HwqOfEgkSN8YFfxwRiCFw1FeJv2rg@mail.gmail.com>
In-Reply-To: <CA+zEjCt04OV++qK5ar+p8HwqOfEgkSN8YFfxwRiCFw1FeJv2rg@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Fri, 1 Apr 2022 14:56:30 +0200
Message-ID: <CA+zEjCuyEsB0cHoL=zepejcRbn9Rwg9nRXLMZCOXe_daSWbvig@mail.gmail.com>
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
 header.i=@canonical.com header.s=20210705 header.b="mye6/+uv";       spf=pass
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

On Fri, Feb 18, 2022 at 11:45 AM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Hi Palmer,
>
> On Thu, Jan 20, 2022 at 11:05 AM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > On Thu, Jan 20, 2022 at 8:30 AM Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> > >
> > > On Thu, Jan 20, 2022 at 5:18 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> > > >
> > > > On Mon, 06 Dec 2021 02:46:44 PST (-0800), alexandre.ghiti@canonical.com wrote:
> > > > > * Please note notable changes in memory layouts and kasan population *
> > > > >
> > > > > This patchset allows to have a single kernel for sv39 and sv48 without
> > > > > being relocatable.
> > > > >
> > > > > The idea comes from Arnd Bergmann who suggested to do the same as x86,
> > > > > that is mapping the kernel to the end of the address space, which allows
> > > > > the kernel to be linked at the same address for both sv39 and sv48 and
> > > > > then does not require to be relocated at runtime.
> > > > >
> > > > > This implements sv48 support at runtime. The kernel will try to
> > > > > boot with 4-level page table and will fallback to 3-level if the HW does not
> > > > > support it. Folding the 4th level into a 3-level page table has almost no
> > > > > cost at runtime.
> > > > >
> > > > > Note that kasan region had to be moved to the end of the address space
> > > > > since its location must be known at compile-time and then be valid for
> > > > > both sv39 and sv48 (and sv57 that is coming).
> > > > >
> > > > > Tested on:
> > > > >   - qemu rv64 sv39: OK
> > > > >   - qemu rv64 sv48: OK
> > > > >   - qemu rv64 sv39 + kasan: OK
> > > > >   - qemu rv64 sv48 + kasan: OK
> > > > >   - qemu rv32: OK
> > > > >
> > > > > Changes in v3:
> > > > >   - Fix SZ_1T, thanks to Atish
> > > > >   - Fix warning create_pud_mapping, thanks to Atish
> > > > >   - Fix k210 nommu build, thanks to Atish
> > > > >   - Fix wrong rebase as noted by Samuel
> > > > >   - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
> > > > >   - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
> > > > >
> > > > > Changes in v2:
> > > > >   - Rebase onto for-next
> > > > >   - Fix KASAN
> > > > >   - Fix stack canary
> > > > >   - Get completely rid of MAXPHYSMEM configs
> > > > >   - Add documentation
> > > > >
> > > > > Alexandre Ghiti (13):
> > > > >   riscv: Move KASAN mapping next to the kernel mapping
> > > > >   riscv: Split early kasan mapping to prepare sv48 introduction
> > > > >   riscv: Introduce functions to switch pt_ops
> > > > >   riscv: Allow to dynamically define VA_BITS
> > > > >   riscv: Get rid of MAXPHYSMEM configs
> > > > >   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
> > > > >   riscv: Implement sv48 support
> > > > >   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
> > > > >   riscv: Explicit comment about user virtual address space size
> > > > >   riscv: Improve virtual kernel memory layout dump
> > > > >   Documentation: riscv: Add sv48 description to VM layout
> > > > >   riscv: Initialize thread pointer before calling C functions
> > > > >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
> > > > >
> > > > >  Documentation/riscv/vm-layout.rst             |  48 ++-
> > > > >  arch/riscv/Kconfig                            |  37 +-
> > > > >  arch/riscv/configs/nommu_k210_defconfig       |   1 -
> > > > >  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
> > > > >  arch/riscv/configs/nommu_virt_defconfig       |   1 -
> > > > >  arch/riscv/include/asm/csr.h                  |   3 +-
> > > > >  arch/riscv/include/asm/fixmap.h               |   1
> > > > >  arch/riscv/include/asm/kasan.h                |  11 +-
> > > > >  arch/riscv/include/asm/page.h                 |  20 +-
> > > > >  arch/riscv/include/asm/pgalloc.h              |  40 ++
> > > > >  arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
> > > > >  arch/riscv/include/asm/pgtable.h              |  47 +-
> > > > >  arch/riscv/include/asm/sparsemem.h            |   6 +-
> > > > >  arch/riscv/kernel/cpu.c                       |  23 +-
> > > > >  arch/riscv/kernel/head.S                      |   4 +-
> > > > >  arch/riscv/mm/context.c                       |   4 +-
> > > > >  arch/riscv/mm/init.c                          | 408 ++++++++++++++----
> > > > >  arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
> > > > >  drivers/firmware/efi/libstub/efi-stub.c       |   2
> > > > >  drivers/pci/controller/pci-xgene.c            |   2 +-
> > > > >  include/asm-generic/pgalloc.h                 |  24 +-
> > > > >  include/linux/sizes.h                         |   1
> > > > >  22 files changed, 833 insertions(+), 209 deletions(-)
> > > >
> > > > Sorry this took a while.  This is on for-next, with a bit of juggling: a
> > > > handful of trivial fixes for configs that were failing to build/boot and
> > > > some merge issues.  I also pulled out that MAXPHYSMEM fix to the top, so
> > > > it'd be easier to backport.  This is bigger than something I'd normally like to
> > > > take late in the cycle, but given there's a lot of cleanups, likely some fixes,
> > > > and it looks like folks have been testing this I'm just going to go with it.
> > > >
> > >
> > > Yes yes yes! That's fantastic news :)
> > >
> > > > Let me know if there's any issues with the merge, it was a bit hairy.
> > > > Probably best to just send along a fixup patch at this point.
> > >
> > > I'm going to take a look at that now, and I'll fix anything that comes
> > > up quickly :)
> >
> > I see in for-next that you did not take the following patches:
> >
> >   riscv: Improve virtual kernel memory layout dump
> >   Documentation: riscv: Add sv48 description to VM layout
> >   riscv: Initialize thread pointer before calling C functions
> >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
> >
> > I'm not sure this was your intention. If it was, I believe that at
> > least the first 2 patches are needed in this series, the 3rd one is a
> > useful fix and we can discuss the 4th if that's an issue for you.
>
> Can you confirm that this was intentional and maybe explain the
> motivation behind it? Because I see value in those patches.

Palmer,

I read that you were still taking patches for 5.18, so I confirm again
that the patches above are needed IMO.

Maybe even the relocatable series?

Thanks,

Alex

>
> Thanks,
>
> Alex
>
> >
> > I tested for-next on both sv39 and sv48 successfully, I took a glance
> > at the code and noticed you fixed the PTRS_PER_PGD error, thanks for
> > that. Otherwise nothing obvious has popped.
> >
> > Thanks again,
> >
> > Alex
> >
> > >
> > > Thanks!
> > >
> > > Alex
> > >
> > > >
> > > > Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuyEsB0cHoL%3DzepejcRbn9Rwg9nRXLMZCOXe_daSWbvig%40mail.gmail.com.
