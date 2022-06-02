Return-Path: <kasan-dev+bncBCRKNY4WZECBBAPE4CKAMGQEVH7USTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 000A453B232
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jun 2022 05:44:02 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id l2-20020a9d7342000000b0060ae5f9fb40sf1040323otk.7
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jun 2022 20:44:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654141441; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wgq9U7nHkfcOlynGhb2EImIeZ5CbLHhMFFthMcYfP1Z0LsjOEjBQEpqOJE3u2ejnrj
         88cqZRiKgdTup9n0yYpHZo2zf+svfv0ItzWfBMXhUDBXuF2PcPrmqhWe1emH2hFojB95
         yypjBoesgMNjPPna3u0ymXmQ/ue+977t+2Q8nL1Jk+dncYUzc4mCs6P3W/eC5NqEgnnd
         556ilcAnLx9BSGPI4AyZwNJ/70kjd66kxH1C+8fkx6Y+S5dv7ceAFFBaI5k+r6Cv6ycN
         K2mB4FqY2/A7qZKVRY2JybJjKQ9zHxpyXO/87G7BUn1XIsUNU4cVENZoRO7g3qSGN6el
         x4Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=6HZA3XYURV68jSXEHX+DDNxUbIc36Urp3iNyd6XUQ6w=;
        b=TCTus5wdk1+GKZZHSsJEE6rnhl/kgxqQEK0u723tGyJ5u5lzZ/AYaYZrrChFqpqIfu
         NN90vghupwR5EyOos6jup8tfCbobUXPexnjvmV8AaO3qTxTFPD2l87g7WitCA1MTMPUd
         hhB+poihaw6j20PrikyJh19sTCG4CRipk00xN6VKB6McepU3ZIIyfnmhwXztAMARbhKe
         kxlmoOYtoTEY1acYYs50zuJxlkHe4v7GJ8tqZMSGvhxsuwW+1XI7u9AkZMI5KglRC/1L
         alS/5bu9xDRlLfUFkGnpDV8gcx09U3INGFxo2LIQb6MFVt/msVdW66CFFLozUDSnRXpo
         310w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=xlIUxlaB;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6HZA3XYURV68jSXEHX+DDNxUbIc36Urp3iNyd6XUQ6w=;
        b=m+n3ZfD/nZNk8WRiyKU9LVkfCTkT2w71/ZKaDzRVJlml3rsHM/CfQzpQRvDuP8WDcU
         V1rVVrWT29DiA9zSnyWMI5T1FljKwZlUcA4BlQpR7kzKOjJFmylubPwJJLA7XNad/Qw2
         lGyvCck3sacnzlSHgytCLGsunJ1fLyJ87i/U8DZ4Ihong4bFwmZBGmqWPe2Qmes02XSb
         oSvaUL3nxGVihMJb65Wk17hq05Fjb2HyGfBKIplRlGDEcSUVYNXu3/QFZ7MnIZG3A+z4
         YcR1ZxuSjIyGbHtHtBXHNWFq1nSQnKdWPq5ON0xsvPE0Dq7pCOqikh/KTvvRtUWZI4ZB
         wcdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6HZA3XYURV68jSXEHX+DDNxUbIc36Urp3iNyd6XUQ6w=;
        b=FUxEkLS06JIKxsJWASAG6uFh7mWtV/PtSNDcdhQFxj3A3Qvz7FCM2zWyOZIJxkK+wD
         q+RTUFiQXOPk9DwgFWRHfwlp+d9RXv/1pfAtp5KXy81QWsXy+lak3pcUQ97c3VplUnfa
         r0OpPRQnVc4qt5beFgX5cBfuSL1JUOAS2VGllyZJdrPa73yd58w5tRxlS/PFHMLT2d4G
         sEHV2w1QPA+6iLSSxIRDq2reivcSKA3dxWRrG3jMX4PjUaYK8fuSFjtHrX72Y3khQIA9
         muPRZBPmRrW2W8iFnzLin5GkvkMU8uPJ0Lt9VjcA4US+P1lMvz+rjmLHEWNbgnsWr6iZ
         DKAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LN3J3LiaRHtclZdYMlHNhaUf8NjgmoXu6b1ZlteOMxtgzVEOT
	BVJncIfTzDHsXZXxV3/INDc=
X-Google-Smtp-Source: ABdhPJw5yJC61gJUy/oDgHzWhi48NS+7VCMArLC5G75+30SgnyJoyYI17VQVXZuuAuV59mp061OWXw==
X-Received: by 2002:a05:6808:1411:b0:32b:ca21:ba08 with SMTP id w17-20020a056808141100b0032bca21ba08mr1616300oiv.124.1654141441419;
        Wed, 01 Jun 2022 20:44:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:23d2:b0:326:98c2:25a8 with SMTP id
 bq18-20020a05680823d200b0032698c225a8ls2123728oib.11.gmail; Wed, 01 Jun 2022
 20:44:01 -0700 (PDT)
X-Received: by 2002:a05:6808:148a:b0:326:c71a:f33c with SMTP id e10-20020a056808148a00b00326c71af33cmr16479035oiw.153.1654141440984;
        Wed, 01 Jun 2022 20:44:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654141440; cv=none;
        d=google.com; s=arc-20160816;
        b=ubYsSp2c/IBUWuQ3lM/BnCtLNKsR2EG7Il3B2T8mvOljlD8vI+wfEBXqtHQlokcqBI
         DIXKyy+srQe6ntDc3h3KEBxDCh+JHc0qsQ61Wh8KYOYRW67iybwpaAKrRSAizlABCm1F
         UOfZR985GNp0EeJ6j9jLsikWEae4dHbRkXE02r4zqHtXh2Q+V/n5nq3TgmKdpfoa+bN6
         QLvFMxdZxX4X4L3Io5CAsqKF4cwY3RbpLk0qK/TIVDkpY6kNnkL4mJm8HQQueKGu7Y51
         onqGafJPrC69cI+KRVfR2M8f6zyYPgbpStgcgVgeigk7Gc8m6NBiy/6z1rGqNu/ookEr
         4Mrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=41Cix8/wz/98CXmQSSNUVoc/eGMSQu30WNS71XR8dIw=;
        b=YzCR+OA6ejlJo6pF8l7rx2f/329RLcGsHENpmsPXIMfzXXfu17xuYSbQoiZURFUcxV
         BUaH81jY0uDoR2m4CrI5a6rnHlFuEwTkKUjPLyK6JDO0yIIIflkXSIpkvlzaQNnm9dYc
         P7INKgSbCBCHAUxKxhorABVE9GzfaC3AwL986bTIEvOVdOhxnvBk4tkELHXELy8vjzhe
         4o6Kke9tXTGdlxr/eroV/hAcTW1NcR+Berx1a+xkNqNxoS2SG8E6z9qVep0DeqSr8Aqs
         6t8G/jt1rCB1qcm1EQSGyAipqBMOz6V9Cx9fUKknIVK77iejJ6sAhk5fCG0qyRU+2gYj
         hqjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=xlIUxlaB;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id ed47-20020a056870b7af00b000f5d73c60c3si444402oab.3.2022.06.01.20.44.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jun 2022 20:44:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id p8so3668312pfh.8
        for <kasan-dev@googlegroups.com>; Wed, 01 Jun 2022 20:44:00 -0700 (PDT)
X-Received: by 2002:a63:6b02:0:b0:3fb:da5e:42a1 with SMTP id g2-20020a636b02000000b003fbda5e42a1mr2388919pgc.273.1654141439808;
        Wed, 01 Jun 2022 20:43:59 -0700 (PDT)
Received: from localhost ([12.3.194.138])
        by smtp.gmail.com with ESMTPSA id g2-20020aa79f02000000b005185407eda5sm2254092pfr.44.2022.06.01.20.43.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Jun 2022 20:43:59 -0700 (PDT)
Date: Wed, 01 Jun 2022 20:43:59 -0700 (PDT)
Subject: Re: [PATCH v3 00/13] Introduce sv48 support without relocatable kernel
In-Reply-To: <mhng-f386a42e-77d9-4644-914f-552a8e721f5c@palmer-ri-x1c9>
CC: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  zong.li@sifive.com, anup@brainfault.org, Atish.Patra@rivosinc.com, Christoph Hellwig <hch@lst.de>,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, ardb@kernel.org,
  Arnd Bergmann <arnd@arndb.de>, keescook@chromium.org, guoren@linux.alibaba.com,
  heinrich.schuchardt@canonical.com, mchitale@ventanamicro.com, panqinglin2020@iscas.ac.cn,
  linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, linux-arch@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-2ff855c7-1f97-46c9-b692-84ea3735eb05@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=xlIUxlaB;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 22 Apr 2022 18:50:47 PDT (-0700), Palmer Dabbelt wrote:
> On Fri, 01 Apr 2022 05:56:30 PDT (-0700), alexandre.ghiti@canonical.com wrote:
>> On Fri, Feb 18, 2022 at 11:45 AM Alexandre Ghiti
>> <alexandre.ghiti@canonical.com> wrote:
>>>
>>> Hi Palmer,
>>>
>>> On Thu, Jan 20, 2022 at 11:05 AM Alexandre Ghiti
>>> <alexandre.ghiti@canonical.com> wrote:
>>> >
>>> > On Thu, Jan 20, 2022 at 8:30 AM Alexandre Ghiti
>>> > <alexandre.ghiti@canonical.com> wrote:
>>> > >
>>> > > On Thu, Jan 20, 2022 at 5:18 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>>> > > >
>>> > > > On Mon, 06 Dec 2021 02:46:44 PST (-0800), alexandre.ghiti@canonical.com wrote:
>>> > > > > * Please note notable changes in memory layouts and kasan population *
>>> > > > >
>>> > > > > This patchset allows to have a single kernel for sv39 and sv48 without
>>> > > > > being relocatable.
>>> > > > >
>>> > > > > The idea comes from Arnd Bergmann who suggested to do the same as x86,
>>> > > > > that is mapping the kernel to the end of the address space, which allows
>>> > > > > the kernel to be linked at the same address for both sv39 and sv48 and
>>> > > > > then does not require to be relocated at runtime.
>>> > > > >
>>> > > > > This implements sv48 support at runtime. The kernel will try to
>>> > > > > boot with 4-level page table and will fallback to 3-level if the HW does not
>>> > > > > support it. Folding the 4th level into a 3-level page table has almost no
>>> > > > > cost at runtime.
>>> > > > >
>>> > > > > Note that kasan region had to be moved to the end of the address space
>>> > > > > since its location must be known at compile-time and then be valid for
>>> > > > > both sv39 and sv48 (and sv57 that is coming).
>>> > > > >
>>> > > > > Tested on:
>>> > > > >   - qemu rv64 sv39: OK
>>> > > > >   - qemu rv64 sv48: OK
>>> > > > >   - qemu rv64 sv39 + kasan: OK
>>> > > > >   - qemu rv64 sv48 + kasan: OK
>>> > > > >   - qemu rv32: OK
>>> > > > >
>>> > > > > Changes in v3:
>>> > > > >   - Fix SZ_1T, thanks to Atish
>>> > > > >   - Fix warning create_pud_mapping, thanks to Atish
>>> > > > >   - Fix k210 nommu build, thanks to Atish
>>> > > > >   - Fix wrong rebase as noted by Samuel
>>> > > > >   - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
>>> > > > >   - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
>>> > > > >
>>> > > > > Changes in v2:
>>> > > > >   - Rebase onto for-next
>>> > > > >   - Fix KASAN
>>> > > > >   - Fix stack canary
>>> > > > >   - Get completely rid of MAXPHYSMEM configs
>>> > > > >   - Add documentation
>>> > > > >
>>> > > > > Alexandre Ghiti (13):
>>> > > > >   riscv: Move KASAN mapping next to the kernel mapping
>>> > > > >   riscv: Split early kasan mapping to prepare sv48 introduction
>>> > > > >   riscv: Introduce functions to switch pt_ops
>>> > > > >   riscv: Allow to dynamically define VA_BITS
>>> > > > >   riscv: Get rid of MAXPHYSMEM configs
>>> > > > >   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
>>> > > > >   riscv: Implement sv48 support
>>> > > > >   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
>>> > > > >   riscv: Explicit comment about user virtual address space size
>>> > > > >   riscv: Improve virtual kernel memory layout dump
>>> > > > >   Documentation: riscv: Add sv48 description to VM layout
>>> > > > >   riscv: Initialize thread pointer before calling C functions
>>> > > > >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
>>> > > > >
>>> > > > >  Documentation/riscv/vm-layout.rst             |  48 ++-
>>> > > > >  arch/riscv/Kconfig                            |  37 +-
>>> > > > >  arch/riscv/configs/nommu_k210_defconfig       |   1 -
>>> > > > >  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
>>> > > > >  arch/riscv/configs/nommu_virt_defconfig       |   1 -
>>> > > > >  arch/riscv/include/asm/csr.h                  |   3 +-
>>> > > > >  arch/riscv/include/asm/fixmap.h               |   1
>>> > > > >  arch/riscv/include/asm/kasan.h                |  11 +-
>>> > > > >  arch/riscv/include/asm/page.h                 |  20 +-
>>> > > > >  arch/riscv/include/asm/pgalloc.h              |  40 ++
>>> > > > >  arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
>>> > > > >  arch/riscv/include/asm/pgtable.h              |  47 +-
>>> > > > >  arch/riscv/include/asm/sparsemem.h            |   6 +-
>>> > > > >  arch/riscv/kernel/cpu.c                       |  23 +-
>>> > > > >  arch/riscv/kernel/head.S                      |   4 +-
>>> > > > >  arch/riscv/mm/context.c                       |   4 +-
>>> > > > >  arch/riscv/mm/init.c                          | 408 ++++++++++++++----
>>> > > > >  arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
>>> > > > >  drivers/firmware/efi/libstub/efi-stub.c       |   2
>>> > > > >  drivers/pci/controller/pci-xgene.c            |   2 +-
>>> > > > >  include/asm-generic/pgalloc.h                 |  24 +-
>>> > > > >  include/linux/sizes.h                         |   1
>>> > > > >  22 files changed, 833 insertions(+), 209 deletions(-)
>>> > > >
>>> > > > Sorry this took a while.  This is on for-next, with a bit of juggling: a
>>> > > > handful of trivial fixes for configs that were failing to build/boot and
>>> > > > some merge issues.  I also pulled out that MAXPHYSMEM fix to the top, so
>>> > > > it'd be easier to backport.  This is bigger than something I'd normally like to
>>> > > > take late in the cycle, but given there's a lot of cleanups, likely some fixes,
>>> > > > and it looks like folks have been testing this I'm just going to go with it.
>>> > > >
>>> > >
>>> > > Yes yes yes! That's fantastic news :)
>>> > >
>>> > > > Let me know if there's any issues with the merge, it was a bit hairy.
>>> > > > Probably best to just send along a fixup patch at this point.
>>> > >
>>> > > I'm going to take a look at that now, and I'll fix anything that comes
>>> > > up quickly :)
>>> >
>>> > I see in for-next that you did not take the following patches:
>>> >
>>> >   riscv: Improve virtual kernel memory layout dump
>>> >   Documentation: riscv: Add sv48 description to VM layout
>>> >   riscv: Initialize thread pointer before calling C functions
>>> >   riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
>>> >
>>> > I'm not sure this was your intention. If it was, I believe that at
>>> > least the first 2 patches are needed in this series, the 3rd one is a
>>> > useful fix and we can discuss the 4th if that's an issue for you.
>>>
>>> Can you confirm that this was intentional and maybe explain the
>>> motivation behind it? Because I see value in those patches.
>>
>> Palmer,
>>
>> I read that you were still taking patches for 5.18, so I confirm again
>> that the patches above are needed IMO.
>
> It was too late for this when it was sent (I saw it then, but just got
> around to actually doing the work to sort it out).
>
> It took me a while to figure out exactly what was going on here, but I
> think I remember now: that downgrade patch (and the follow-on I just
> sent) is broken for medlow, because mm/init.c must be built medany
> (which we're using for the mostly-PIC qualities).  I remember being in
> the middle of rebasing/debugging this a while ago, I must have forgotten
> I was in the middle of that and accidentally merged the branch as-is.
> Certainly wasn't trying to silently take half the patch set and leave
> the rest in limbo, that's the wrong way to do things.
>
> I'm not sure what the right answer is here, but I just sent a patch to
> drop support for medlow.  We'll have to talk about that, for now I
> cleaned up some other minor issues, rearranged that docs and fix to come
> first, and put this at palmer/riscv-sv48.  I think that fix is
> reasonable to take the doc and fix into fixes, then the dump improvement
> on for-next.  We'll have to see what folks think about the medany-only
> kernels, the other option would be to build FDT as medany which seems a
> bit awkward.

All but the last one are on for-next, there's some discussion on that 
last one that pointed out some better ways to do it.

>
>> Maybe even the relocatable series?
>
> Do you mind giving me a pointer?  I'm not sure why I'm so drop-prone
> with your patches, I promise I'm not doing it on purpose.
>
>>
>> Thanks,
>>
>> Alex
>>
>>>
>>> Thanks,
>>>
>>> Alex
>>>
>>> >
>>> > I tested for-next on both sv39 and sv48 successfully, I took a glance
>>> > at the code and noticed you fixed the PTRS_PER_PGD error, thanks for
>>> > that. Otherwise nothing obvious has popped.
>>> >
>>> > Thanks again,
>>> >
>>> > Alex
>>> >
>>> > >
>>> > > Thanks!
>>> > >
>>> > > Alex
>>> > >
>>> > > >
>>> > > > Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-2ff855c7-1f97-46c9-b692-84ea3735eb05%40palmer-ri-x1c9.
