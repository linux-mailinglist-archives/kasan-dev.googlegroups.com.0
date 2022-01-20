Return-Path: <kasan-dev+bncBCRKNY4WZECBBBGFUOHQMGQE4ULMZBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 49C6D49465A
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jan 2022 05:18:14 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id n23-20020a17090a161700b001b3ea76b406sf5331113pja.5
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jan 2022 20:18:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642652292; cv=pass;
        d=google.com; s=arc-20160816;
        b=jdcgJDsyMxlhqvFDM7ct1vtLO+cyZ8pAuZOb/mdwHi+GBrvmq6nCZ6MFI0qYK/Tj9Y
         bn7cFrSiSH/hbHgOwUMWd8nNWrH0hE0r2R3hrTGWFTd+Bfgrp2IKmBlbvhAAOATwwk2+
         v/cEqjUbMipYTX/3DRzb5RRVErQdAIf0ExwTlNKGmNncIV7EcNNqNlZ4rzrs/H1tNVA8
         220ykb0WRXjTTwcoeyUb8AX6Fu5BMLXLvSBqmW7OyYjMYH5iBGx9amugr3Yoj/IUeO7a
         jTn6vmLfdpeM6+A61QoSj037TPyAZ6zeR21ggxdC1RVGQcO4N69lq3IH9Z3i7xwX7f/N
         FMvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=9rpodXLiL7snqeYB0VDOJWsFFXHIsKYsmqYXjWH0A1Q=;
        b=rW8bhXuLUh3Sekw5Ef2coLxiGchAZ04MsKis7b+QQZ1zCmSteYB7HUE4SFNw0ROluE
         wCaHjinVad2ZgFo0xosnBNq2Bx1sXeMRZpwG89v9LbcTupU/e1O1lCAciIAt+v38QbFS
         /WQAwe6fd/hE4okLZB8LxA+/HWRlzBkseYfMUu0Kr/Ot85GAkv3eirA1Wat0rKudKrGe
         b1CNslwzD0VZ3uGZt/nTAOnozegaOvf1zC+Y+VwCLtNZdbd6EsM4rW6M/AIl7cCNDyZQ
         9ERY/X0gqwsSbeBjzBjKZnkceniqE3K9xFR4fprtpOTdwTsaYVQH0o4QiFawBt4/VKSJ
         S5TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=DjFVfnxN;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9rpodXLiL7snqeYB0VDOJWsFFXHIsKYsmqYXjWH0A1Q=;
        b=WF4YcTC+t720yVzAbzS86wyKrH58szd22ofdbwwgyexmb76rRhOVyvkBpjQHtSFgTu
         sRZH/NWl15+H1gGf1XA31o7nm/ZB36+NDwrZU/665CzMGNmJxdOePpvKYnARtKI28zXt
         XJFuA9gtsbLND47FMETP0Hb99CubwyuCdkYJJVaQ+2ctbG9NandhpGNQHBapfHkZVTd3
         iReX/ea7RmKny06hMNhJCJFbnuLU9IzBWAu3sPOurI3VtlKmIEskA1/fPUVDCXRo+s1f
         RmjNjN0CoqSuLzojxFPp1rtA1WQIqFxjEl45pWrahvGuokHCR7cLZGCr904IGW453NDm
         p8Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9rpodXLiL7snqeYB0VDOJWsFFXHIsKYsmqYXjWH0A1Q=;
        b=cHgXZ3Z9jD1+NCbBTYXOHnPmBvAWBwgcedmOzqVOFSo7A3wwLaOuYlqFBQDcJSYeeb
         4Bh+X4ORpsdfquCFkyJLBpu6iJVR4MlokpLHsGzhEPVYAndLY8BZ+RhxUGqk3/00/GOE
         lqD6zRxfum4n/OyNM6FddxOQi5ut0EBIPqjDFGyv8OMwsa6t6Wbmy79OV55zZ5M56oPJ
         +Y46jyFw8c3O6mDzfakoUZ/m1MQUKRqhKmwyd6EXXttQlVilZBA2HIYz+2E94CpnCKdf
         Y9WLnDP6Vlm63N+45QHU592TR3M9a8pLeYQYqiHSyzovXw3eMCQ1rdZj4areaIQFD7w+
         VfCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cYcorxNX3RPnBEI8gFpfqRDT9tOxzKBZW3hRIpveTpRdA479+
	xM3vxdgPaLW4P/vNKpHQav4=
X-Google-Smtp-Source: ABdhPJxgrc3laXEeLXuQUdM7hukRyrvpaGvS2PlY0IBGtIg2WrJOQGNfah37wS6djAN/Rh1KY6RUvg==
X-Received: by 2002:a17:90b:4a45:: with SMTP id lb5mr8462723pjb.220.1642652292419;
        Wed, 19 Jan 2022 20:18:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6ab6:: with SMTP id x22ls1386709pgu.8.gmail; Wed, 19 Jan
 2022 20:18:11 -0800 (PST)
X-Received: by 2002:a63:4510:: with SMTP id s16mr10298919pga.578.1642652291822;
        Wed, 19 Jan 2022 20:18:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642652291; cv=none;
        d=google.com; s=arc-20160816;
        b=E6YltgER5U2DlsPQHaG4lxwgQMml78P0EVltbWSBxowkWfNGiiDQ7G5w/DjmyEyxF6
         R2YV9f/N6lyhuCzMspopIsxmek5CC37cqrRGcVTQoPfkiiO7Ba55C6jb8lY+yE+nY+Ah
         VYICtzEmJoBSher4ZFF+kx2vDOK39bKNqMdCyMjN5mM7tAERyvJybmni7V02/XxWBOF5
         OnRaJupVvIpGRMj+n69lT0ojulNgwVaE/5TziDgCp72SvgJJ+G3A5zEqbrOi6BzyMRH+
         e+iU3xytMm4bl/s9pwb0Pgd7e0MRleh6zib+u1xswtmnz4EpD5c7sB1T3iCQeRQACkyK
         9yrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=iT9AIdLj55ev5yKtI8ieivVAM11HecgPIKI9gy4uM7k=;
        b=x6PSD90xT3bA9ChXeI344/egaYe2nky4kSI/Ae6iMkwECcqhyVVj0iaVWSj5uDEsPu
         DsCtCw2daeHiCup88OhHzH4PwHOWRP/qEzXqtolqFjZ8W+Uezop1UQtB5rrJITfvhCK2
         Ac9U+1e4WoLwd7MU76CymM9JCYUf79coQw/+kD6kG6S/1Cjl5pHDGxo7MBNslO7MA5iJ
         MkCfoDXvjkAcrxnZho4Dqj5AY8fAvOF2rND/zndgy17jmai5MMiDoc5vltFtq6CFoaJI
         kP4bLTiW1jpa3L8i7KNnnoXwv1Q+RffyvCvtaxi+tGL++dAzrmeqVFNbgLHDz4P7WwSv
         sg7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=DjFVfnxN;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 207si108946pfx.6.2022.01.19.20.18.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Jan 2022 20:18:11 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d1so4128818plh.10
        for <kasan-dev@googlegroups.com>; Wed, 19 Jan 2022 20:18:11 -0800 (PST)
X-Received: by 2002:a17:902:704c:b0:14a:fd51:3b5d with SMTP id h12-20020a170902704c00b0014afd513b5dmr3945207plt.172.1642652291221;
        Wed, 19 Jan 2022 20:18:11 -0800 (PST)
Received: from localhost ([12.3.194.138])
        by smtp.gmail.com with ESMTPSA id t7sm1081924pfj.138.2022.01.19.20.18.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jan 2022 20:18:10 -0800 (PST)
Date: Wed, 19 Jan 2022 20:18:10 -0800 (PST)
Subject: Re: [PATCH v3 00/13] Introduce sv48 support without relocatable kernel
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
CC: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  zong.li@sifive.com, anup@brainfault.org, Atish.Patra@rivosinc.com, Christoph Hellwig <hch@lst.de>,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, ardb@kernel.org,
  Arnd Bergmann <arnd@arndb.de>, keescook@chromium.org, guoren@linux.alibaba.com,
  heinrich.schuchardt@canonical.com, mchitale@ventanamicro.com, panqinglin2020@iscas.ac.cn,
  linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, linux-arch@vger.kernel.org,
  alexandre.ghiti@canonical.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-cdec292e-aea2-4b76-8853-b8465521e94f@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=DjFVfnxN;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 06 Dec 2021 02:46:44 PST (-0800), alexandre.ghiti@canonical.com wrote:
> * Please note notable changes in memory layouts and kasan population *
>
> This patchset allows to have a single kernel for sv39 and sv48 without
> being relocatable.
>
> The idea comes from Arnd Bergmann who suggested to do the same as x86,
> that is mapping the kernel to the end of the address space, which allows
> the kernel to be linked at the same address for both sv39 and sv48 and
> then does not require to be relocated at runtime.
>
> This implements sv48 support at runtime. The kernel will try to
> boot with 4-level page table and will fallback to 3-level if the HW does not
> support it. Folding the 4th level into a 3-level page table has almost no
> cost at runtime.
>
> Note that kasan region had to be moved to the end of the address space
> since its location must be known at compile-time and then be valid for
> both sv39 and sv48 (and sv57 that is coming).
>
> Tested on:
>   - qemu rv64 sv39: OK
>   - qemu rv64 sv48: OK
>   - qemu rv64 sv39 + kasan: OK
>   - qemu rv64 sv48 + kasan: OK
>   - qemu rv32: OK
>
> Changes in v3:
>   - Fix SZ_1T, thanks to Atish
>   - Fix warning create_pud_mapping, thanks to Atish
>   - Fix k210 nommu build, thanks to Atish
>   - Fix wrong rebase as noted by Samuel
>   - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
>   - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
>
> Changes in v2:
>   - Rebase onto for-next
>   - Fix KASAN
>   - Fix stack canary
>   - Get completely rid of MAXPHYSMEM configs
>   - Add documentation
>
> Alexandre Ghiti (13):
>   riscv: Move KASAN mapping next to the kernel mapping
>   riscv: Split early kasan mapping to prepare sv48 introduction
>   riscv: Introduce functions to switch pt_ops
>   riscv: Allow to dynamically define VA_BITS
>   riscv: Get rid of MAXPHYSMEM configs
>   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
>   riscv: Implement sv48 support
>   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
>   riscv: Explicit comment about user virtual address space size
>   riscv: Improve virtual kernel memory layout dump
>   Documentation: riscv: Add sv48 description to VM layout
>   riscv: Initialize thread pointer before calling C functions
>   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
>
>  Documentation/riscv/vm-layout.rst             |  48 ++-
>  arch/riscv/Kconfig                            |  37 +-
>  arch/riscv/configs/nommu_k210_defconfig       |   1 -
>  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
>  arch/riscv/configs/nommu_virt_defconfig       |   1 -
>  arch/riscv/include/asm/csr.h                  |   3 +-
>  arch/riscv/include/asm/fixmap.h               |   1
>  arch/riscv/include/asm/kasan.h                |  11 +-
>  arch/riscv/include/asm/page.h                 |  20 +-
>  arch/riscv/include/asm/pgalloc.h              |  40 ++
>  arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
>  arch/riscv/include/asm/pgtable.h              |  47 +-
>  arch/riscv/include/asm/sparsemem.h            |   6 +-
>  arch/riscv/kernel/cpu.c                       |  23 +-
>  arch/riscv/kernel/head.S                      |   4 +-
>  arch/riscv/mm/context.c                       |   4 +-
>  arch/riscv/mm/init.c                          | 408 ++++++++++++++----
>  arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
>  drivers/firmware/efi/libstub/efi-stub.c       |   2
>  drivers/pci/controller/pci-xgene.c            |   2 +-
>  include/asm-generic/pgalloc.h                 |  24 +-
>  include/linux/sizes.h                         |   1
>  22 files changed, 833 insertions(+), 209 deletions(-)

Sorry this took a while.  This is on for-next, with a bit of juggling: a 
handful of trivial fixes for configs that were failing to build/boot and 
some merge issues.  I also pulled out that MAXPHYSMEM fix to the top, so 
it'd be easier to backport.  This is bigger than something I'd normally like to
take late in the cycle, but given there's a lot of cleanups, likely some fixes,
and it looks like folks have been testing this I'm just going to go with it.

Let me know if there's any issues with the merge, it was a bit hairy.  
Probably best to just send along a fixup patch at this point.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-cdec292e-aea2-4b76-8853-b8465521e94f%40palmer-ri-x1c9.
