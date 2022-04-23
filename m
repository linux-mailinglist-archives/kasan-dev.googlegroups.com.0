Return-Path: <kasan-dev+bncBCRKNY4WZECBB6NWRWJQMGQEJVHDKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 76FF650C633
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Apr 2022 03:50:51 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id t19-20020a4a96d3000000b003295d7ce159sf4774092ooi.11
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 18:50:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650678650; cv=pass;
        d=google.com; s=arc-20160816;
        b=F2s8TMuZRBRAV+x4m1HoVGTnAYxOIl+nO3BkGu/pp8RAayeaO9R/wJqCTGQPZdhkZ1
         w4W0Qpua6aBpxZfnxq1yHZlNt1okMecziKobyWK3O/Gvi/y83SF3KFX5GMYKmBm7rGmz
         hiOT2eubcqHMhTcZGFinJ93tk/UpPprZ6mgtc3QpqFE4gXTywSdzry2M3dUtgDqbVzlP
         n+wSROkFY2KuIlKAWOcyH7p+OMCOr3irYjZR1Zmig7Oxi3Ef3QjnbH1rjo4ycZFsAFy6
         npGUQvc78wTMQuhSZAfHmSGaCeEdDxu7uNXj/KECzD+qwxRpudsmjBe8QMMZ2cn8icip
         5HGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=wq5skWqsCJa2gcZlGV2sNNPu0cGBJKtokxfv5f/BbME=;
        b=LtXjmBGIpFua3Z2lN9t+CkKC/9wdqeVEOqr1rPlG3V2VPLFRz/ifuQMXqGJW8g75lB
         slUuZOFH1ANLRVqACzsqejCfLycYIWaAUd+doF+WoaHZ73VdTBgCsYCv/9j8SuPD9DYY
         eH/ehFkbjJq26mYzrR00ElUW1pr0cJg1K5tgqskficK0O9O6mOIMOdd70ZiAnQNw+sS5
         6KgU9av+ONdfnMtWXfCeaufHJko/+7QYF9BzYPbHohrCgrHbdsieAGOF3mw6gANsp4wm
         n4ygjR5Z0/e3KZfnNA5ElWXbRiZ3JUaIOVwKHcSypvNQgJgoywdSPaVAJ+8Xb/dObEri
         p0Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=goIqv8VM;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wq5skWqsCJa2gcZlGV2sNNPu0cGBJKtokxfv5f/BbME=;
        b=LDD/EPLUfHxJ/uvGQK/s0YFNr7Mo8iEWmbjjzTQZwWartWneeZ+oc6nHmY21e4IfhY
         Z4VTMVEpJlPCqq8St3khX5tH1zV6i/bJSjwncwk72wOiFvnbT3X1XcGf5yFtvsSqU7Ke
         S05606Ladt+Ger2VuroFwGpt8XSsPle3NFRIU6nlYJ1ONWiIVxx2kMJXg0GB1mtC9HVD
         Ncm2K5MUt7FKA25mx50hbSaZtqedHFCosU8WADwcv45NG0dqNyfsESQa8ror/ps5R1cA
         Xv0Mf91TvGm3+oiIBzrdpzt7U/pAiy0UgIFwTQb4W59TQKSewcWOWxJQutrml6kZaj2i
         zk8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wq5skWqsCJa2gcZlGV2sNNPu0cGBJKtokxfv5f/BbME=;
        b=rg/aTeh3XQrMM+l6ZaVfcwYIXcOG+UDQ4BZDwozPbNYpHFpjnHtV2ML5GLNS52WdvZ
         QhwYEMmM/1P/1ObFqoV8LixvKwtBYexubjDORsXyXMnYf1fDhsbPW5wCnbd7IZ4WRe6v
         kuuKewrUrn37biy73csnDj2YOB7ihrfgMQ72wxm8YwQLBOLXPoDx2zhMu37al3tOOoer
         1ZaKJMNIwdTxT1hRFCe2w2x2ezAPBuOngLFNWyzWGZjFOq8Su/3Psbzc1uZibqI3Fylm
         u2+iCJopkjfdjuy7YaVO383qh7YqDF3UZAWZ3083YhAgvRHgfuQov4yGy5ZPHf3k46aZ
         PjcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531V1HRmBuFiztgktaNZS2xnZAtmmc2xikwInMHTpOEsddEVZQIp
	c0OK0mkzqW888isUbsC9EI8=
X-Google-Smtp-Source: ABdhPJz9C1nScvHk4qEJHdsjmIzZa7QgPY/9OkpqtzMDYZllJ0qlFx0TPo8fjDo6/K/KY915C89aBA==
X-Received: by 2002:a05:6870:a985:b0:dd:fb7f:8e3f with SMTP id ep5-20020a056870a98500b000ddfb7f8e3fmr3297988oab.267.1650678650014;
        Fri, 22 Apr 2022 18:50:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2a8a:b0:605:55d2:4318 with SMTP id
 s10-20020a0568302a8a00b0060555d24318ls500453otu.11.gmail; Fri, 22 Apr 2022
 18:50:49 -0700 (PDT)
X-Received: by 2002:a9d:67c8:0:b0:605:4644:fe23 with SMTP id c8-20020a9d67c8000000b006054644fe23mr2884360otn.105.1650678649477;
        Fri, 22 Apr 2022 18:50:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650678649; cv=none;
        d=google.com; s=arc-20160816;
        b=dFiSUhBS/SFOsQEAgoecxiD3R/KQpn1n9e5h9HXvjp5+0azmbwcuhFGmo0OYpiv5u0
         c5HykKVqogwPc1HRuSnCOk1PcUXqmkZj5yruYaFTse9foEpLl8GtnZSe2oBz3LGn70mS
         vE/MqE5SN0+MkH6EVv+glTiBYKVe8pHNZne1yAcCCK5B+oiTLmKFs79a71sHwKR7Ctjo
         qbxgihL0eS8d4l5mBIr51RsVEc7czphv+rTD4UxL1ceSqJSgcw+YpaMLH0/KIerd0e4B
         zbaZznTJrJZGsq9jT0I7YhaZA+JCl4tgf+XLoS7yhRN4uOyExUT89f27mzzSj3VbVdWd
         Mp6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=iuHt4Iz4FeZBvfTekgoBxhqf7wWZiBSKlKE/b+2tuYo=;
        b=Y108TW3Nk5gXP3XRZB+KjYb4fZyZ8DC0XMJ2+szHtiTObcsAgcHBoqfHH+qcNWQdX1
         kyj7ZTVPZP5+Lf15TNNl7yCS3bYKQnWy7znp4svS7oWwtPH7VMLW5omYMiWe8zOURq1I
         juABdQmDfsK8HSWo6ZwfePL1nNGzCdBlq/1r+NqDWynQ6dKdz+oTnLNBNFOMcHW5OY4I
         HeHncvyyOzXpKEqyI0PlmaICFwGnfI0G/6ABu9ep9ETQYS4rUlcAAYwW791n8lPAue0+
         5MWr9Bd1wMXRmKSELUdglJPiADPXnXJlzqnkrDsw94XFkSYf/5nC/abO1faSHNnr/7RC
         tMkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=goIqv8VM;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id eg4-20020a056870988400b000ddac42441esi1093477oab.0.2022.04.22.18.50.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 18:50:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id w16so3128388pfj.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 18:50:49 -0700 (PDT)
X-Received: by 2002:a63:c5:0:b0:3aa:9882:9f91 with SMTP id 188-20020a6300c5000000b003aa98829f91mr6164187pga.574.1650678648423;
        Fri, 22 Apr 2022 18:50:48 -0700 (PDT)
Received: from localhost ([12.3.194.138])
        by smtp.gmail.com with ESMTPSA id 123-20020a620681000000b004fa7c20d732sm3684931pfg.133.2022.04.22.18.50.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Apr 2022 18:50:47 -0700 (PDT)
Date: Fri, 22 Apr 2022 18:50:47 -0700 (PDT)
Subject: Re: [PATCH v3 00/13] Introduce sv48 support without relocatable kernel
In-Reply-To: <CA+zEjCuyEsB0cHoL=zepejcRbn9Rwg9nRXLMZCOXe_daSWbvig@mail.gmail.com>
CC: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  zong.li@sifive.com, anup@brainfault.org, Atish.Patra@rivosinc.com, Christoph Hellwig <hch@lst.de>,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, ardb@kernel.org,
  Arnd Bergmann <arnd@arndb.de>, keescook@chromium.org, guoren@linux.alibaba.com,
  heinrich.schuchardt@canonical.com, mchitale@ventanamicro.com, panqinglin2020@iscas.ac.cn,
  linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, linux-arch@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-f386a42e-77d9-4644-914f-552a8e721f5c@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=goIqv8VM;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 01 Apr 2022 05:56:30 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> On Fri, Feb 18, 2022 at 11:45 AM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
>>
>> Hi Palmer,
>>
>> On Thu, Jan 20, 2022 at 11:05 AM Alexandre Ghiti
>> <alexandre.ghiti@canonical.com> wrote:
>> >
>> > On Thu, Jan 20, 2022 at 8:30 AM Alexandre Ghiti
>> > <alexandre.ghiti@canonical.com> wrote:
>> > >
>> > > On Thu, Jan 20, 2022 at 5:18 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>> > > >
>> > > > On Mon, 06 Dec 2021 02:46:44 PST (-0800), alexandre.ghiti@canonical.com wrote:
>> > > > > * Please note notable changes in memory layouts and kasan population *
>> > > > >
>> > > > > This patchset allows to have a single kernel for sv39 and sv48 without
>> > > > > being relocatable.
>> > > > >
>> > > > > The idea comes from Arnd Bergmann who suggested to do the same as x86,
>> > > > > that is mapping the kernel to the end of the address space, which allows
>> > > > > the kernel to be linked at the same address for both sv39 and sv48 and
>> > > > > then does not require to be relocated at runtime.
>> > > > >
>> > > > > This implements sv48 support at runtime. The kernel will try to
>> > > > > boot with 4-level page table and will fallback to 3-level if the HW does not
>> > > > > support it. Folding the 4th level into a 3-level page table has almost no
>> > > > > cost at runtime.
>> > > > >
>> > > > > Note that kasan region had to be moved to the end of the address space
>> > > > > since its location must be known at compile-time and then be valid for
>> > > > > both sv39 and sv48 (and sv57 that is coming).
>> > > > >
>> > > > > Tested on:
>> > > > >   - qemu rv64 sv39: OK
>> > > > >   - qemu rv64 sv48: OK
>> > > > >   - qemu rv64 sv39 + kasan: OK
>> > > > >   - qemu rv64 sv48 + kasan: OK
>> > > > >   - qemu rv32: OK
>> > > > >
>> > > > > Changes in v3:
>> > > > >   - Fix SZ_1T, thanks to Atish
>> > > > >   - Fix warning create_pud_mapping, thanks to Atish
>> > > > >   - Fix k210 nommu build, thanks to Atish
>> > > > >   - Fix wrong rebase as noted by Samuel
>> > > > >   - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
>> > > > >   - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
>> > > > >
>> > > > > Changes in v2:
>> > > > >   - Rebase onto for-next
>> > > > >   - Fix KASAN
>> > > > >   - Fix stack canary
>> > > > >   - Get completely rid of MAXPHYSMEM configs
>> > > > >   - Add documentation
>> > > > >
>> > > > > Alexandre Ghiti (13):
>> > > > >   riscv: Move KASAN mapping next to the kernel mapping
>> > > > >   riscv: Split early kasan mapping to prepare sv48 introduction
>> > > > >   riscv: Introduce functions to switch pt_ops
>> > > > >   riscv: Allow to dynamically define VA_BITS
>> > > > >   riscv: Get rid of MAXPHYSMEM configs
>> > > > >   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
>> > > > >   riscv: Implement sv48 support
>> > > > >   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
>> > > > >   riscv: Explicit comment about user virtual address space size
>> > > > >   riscv: Improve virtual kernel memory layout dump
>> > > > >   Documentation: riscv: Add sv48 description to VM layout
>> > > > >   riscv: Initialize thread pointer before calling C functions
>> > > > >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
>> > > > >
>> > > > >  Documentation/riscv/vm-layout.rst             |  48 ++-
>> > > > >  arch/riscv/Kconfig                            |  37 +-
>> > > > >  arch/riscv/configs/nommu_k210_defconfig       |   1 -
>> > > > >  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
>> > > > >  arch/riscv/configs/nommu_virt_defconfig       |   1 -
>> > > > >  arch/riscv/include/asm/csr.h                  |   3 +-
>> > > > >  arch/riscv/include/asm/fixmap.h               |   1
>> > > > >  arch/riscv/include/asm/kasan.h                |  11 +-
>> > > > >  arch/riscv/include/asm/page.h                 |  20 +-
>> > > > >  arch/riscv/include/asm/pgalloc.h              |  40 ++
>> > > > >  arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
>> > > > >  arch/riscv/include/asm/pgtable.h              |  47 +-
>> > > > >  arch/riscv/include/asm/sparsemem.h            |   6 +-
>> > > > >  arch/riscv/kernel/cpu.c                       |  23 +-
>> > > > >  arch/riscv/kernel/head.S                      |   4 +-
>> > > > >  arch/riscv/mm/context.c                       |   4 +-
>> > > > >  arch/riscv/mm/init.c                          | 408 ++++++++++++++----
>> > > > >  arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
>> > > > >  drivers/firmware/efi/libstub/efi-stub.c       |   2
>> > > > >  drivers/pci/controller/pci-xgene.c            |   2 +-
>> > > > >  include/asm-generic/pgalloc.h                 |  24 +-
>> > > > >  include/linux/sizes.h                         |   1
>> > > > >  22 files changed, 833 insertions(+), 209 deletions(-)
>> > > >
>> > > > Sorry this took a while.  This is on for-next, with a bit of juggling: a
>> > > > handful of trivial fixes for configs that were failing to build/boot and
>> > > > some merge issues.  I also pulled out that MAXPHYSMEM fix to the top, so
>> > > > it'd be easier to backport.  This is bigger than something I'd normally like to
>> > > > take late in the cycle, but given there's a lot of cleanups, likely some fixes,
>> > > > and it looks like folks have been testing this I'm just going to go with it.
>> > > >
>> > >
>> > > Yes yes yes! That's fantastic news :)
>> > >
>> > > > Let me know if there's any issues with the merge, it was a bit hairy.
>> > > > Probably best to just send along a fixup patch at this point.
>> > >
>> > > I'm going to take a look at that now, and I'll fix anything that comes
>> > > up quickly :)
>> >
>> > I see in for-next that you did not take the following patches:
>> >
>> >   riscv: Improve virtual kernel memory layout dump
>> >   Documentation: riscv: Add sv48 description to VM layout
>> >   riscv: Initialize thread pointer before calling C functions
>> >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
>> >
>> > I'm not sure this was your intention. If it was, I believe that at
>> > least the first 2 patches are needed in this series, the 3rd one is a
>> > useful fix and we can discuss the 4th if that's an issue for you.
>>
>> Can you confirm that this was intentional and maybe explain the
>> motivation behind it? Because I see value in those patches.
>
> Palmer,
>
> I read that you were still taking patches for 5.18, so I confirm again
> that the patches above are needed IMO.

It was too late for this when it was sent (I saw it then, but just got 
around to actually doing the work to sort it out).

It took me a while to figure out exactly what was going on here, but I 
think I remember now: that downgrade patch (and the follow-on I just 
sent) is broken for medlow, because mm/init.c must be built medany 
(which we're using for the mostly-PIC qualities).  I remember being in 
the middle of rebasing/debugging this a while ago, I must have forgotten 
I was in the middle of that and accidentally merged the branch as-is.  
Certainly wasn't trying to silently take half the patch set and leave 
the rest in limbo, that's the wrong way to do things. 

I'm not sure what the right answer is here, but I just sent a patch to 
drop support for medlow.  We'll have to talk about that, for now I 
cleaned up some other minor issues, rearranged that docs and fix to come 
first, and put this at palmer/riscv-sv48.  I think that fix is 
reasonable to take the doc and fix into fixes, then the dump improvement 
on for-next.  We'll have to see what folks think about the medany-only 
kernels, the other option would be to build FDT as medany which seems a 
bit awkward.  

> Maybe even the relocatable series?

Do you mind giving me a pointer?  I'm not sure why I'm so drop-prone 
with your patches, I promise I'm not doing it on purpose.

>
> Thanks,
>
> Alex
>
>>
>> Thanks,
>>
>> Alex
>>
>> >
>> > I tested for-next on both sv39 and sv48 successfully, I took a glance
>> > at the code and noticed you fixed the PTRS_PER_PGD error, thanks for
>> > that. Otherwise nothing obvious has popped.
>> >
>> > Thanks again,
>> >
>> > Alex
>> >
>> > >
>> > > Thanks!
>> > >
>> > > Alex
>> > >
>> > > >
>> > > > Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-f386a42e-77d9-4644-914f-552a8e721f5c%40palmer-ri-x1c9.
