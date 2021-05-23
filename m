Return-Path: <kasan-dev+bncBCRKNY4WZECBBKEAU6CQMGQE6F24SMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F8A638D855
	for <lists+kasan-dev@lfdr.de>; Sun, 23 May 2021 04:38:34 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id c25-20020a4ad7990000b029020e67cc1879sf13667998oou.18
        for <lists+kasan-dev@lfdr.de>; Sat, 22 May 2021 19:38:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621737513; cv=pass;
        d=google.com; s=arc-20160816;
        b=BDwL8cGs/WkbUigZ7kM9ivaBYGBo1eWCK8ml702trBm7Rcj2HmaRHwnpP3XtnEnSJN
         awyVxC8JeZBmWovcXXK5hVGqYPw7DE8xCJBPDTPqNtFWka7zQhe206aCxL6aTFnv0XQB
         7DjWJu/ZfMkrMLe+2fF328sQ6Tsm17xV0a1y3NfYTzwhs35fL08fiUzBT8WS8EFd0QkU
         1jhBP6i53iZdCt4KzKbtzDM0gEVqKQ+HTXQVgAr8Lpkrn46pqCUT3vOchQbR4UMOkRYt
         v6xIj9mRJAfjSJPuTtBGwbxKFoIeAH85zfQnRmRurkvUxzADI3zfYMMtG4oAfw8RPBHt
         MyVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=fcKttAnVpVfgite/KJua0jgW2vmFkgBzGsGvdvctSlw=;
        b=QJB6u+/9CrV2z3g0hvaPRxYnQw5GbepYldpPuRYGDHfQzZPoBVJdCjNvXvtRTj+rqL
         PmWeUwFiUutW1oW9qV5o/Y79sx3ALcTPYaWiJYsLFouxLAr9WV58JCCX6LGmfwiOnPCd
         SPD5gCguik019N4Nis8BBRmuMK2p19suQ50bxs2wa8ktSv+LWTzZR4vSifCVerV+5gSq
         5WKZhyjOnjY6as/Bbkvo9lQcR0yfXnAD1xZuWxHDNMT6c1BsZEJ3UQM5T+Y46iegd2kx
         t/iYZlrPtymtg7Ep8weNXMhHBHu/8PqU9i841I4jQ88qmW6RD+s72kY1GwiX1bfO/yqi
         8cpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=a5VDk9Ml;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fcKttAnVpVfgite/KJua0jgW2vmFkgBzGsGvdvctSlw=;
        b=SBj4P6MRb1KkngrX2w/S949MI4A4cszYyoYVJoOVNNyAZM3AxrC0iOuJHzKeS/fx6k
         xHNSo8m5ZTh/bRwSVs9eVjI6Nhxm66w7wPACNM2nECH7dN+/ja+/4UsF/S6tvae5i434
         k3pVXdjyKki6f3qy6DWXDSUhWDTJNkHNI8B1Ti9xgBIvHWVm/fdWr0NfSndtRadvjI2k
         b0uC8Ku1ul1i9izYRm1dZGRfrTIpYP5iZv9yaxYgJGA+AAIOj4ytf4iLj3VAgV7LmHgT
         7IuEgirSPFDjEXjOjw66lgHHwH9k012IbPDdfRlz5YitT2tn6r9Wi67v8ii54rfl4J0p
         qucw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fcKttAnVpVfgite/KJua0jgW2vmFkgBzGsGvdvctSlw=;
        b=CUPAJk1pF6h45lSniXFvFakuF258ZKHexuBryBH1PWVdKvmAZhJIaAtmB/DGWDJpEz
         4OFImCt4ozNg9WP0Tvl1FOdR+/wtwaBFqAT2G0lTBRa8xQy54hrYjhz4QxCTRBQGocR7
         OBYPPtqbN/EqH6PTipESR98Ah2DjO1GG5XfXDcweQNDpolSsxDyLGGnMtwfmCAQeBZLA
         HADGmNS2d18P4ENlJyfOxy0gBzB9UsHBAW8iltpUUtHApXh+03ePAzV+cW7mYtUTzew0
         QeQNhlbWDJjasNAai35BGkdhRmUk7A6HMuZJz/nMKI5Pw+e1t7kvmV8Am+VoYzAAFEiE
         fEYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532gH/ZUCuNd4W1jaocQInibut9fTFh7f8dfk+h5Ci9j/BpITmL8
	W4a/VpQ4gEavv4URXlNRdZ0=
X-Google-Smtp-Source: ABdhPJyGMll3Z+dodpuNba1G3PIoXo41mtRYb0/4kMIjFEXuVHKfv6QKdzkRvFPROkvqcSw+A/5gaA==
X-Received: by 2002:a05:6830:33ea:: with SMTP id i10mr13837980otu.212.1621737512956;
        Sat, 22 May 2021 19:38:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f16:: with SMTP id u22ls3224085otg.7.gmail; Sat,
 22 May 2021 19:38:32 -0700 (PDT)
X-Received: by 2002:a9d:225:: with SMTP id 34mr13616062otb.330.1621737512612;
        Sat, 22 May 2021 19:38:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621737512; cv=none;
        d=google.com; s=arc-20160816;
        b=gyzymIUKU1cDSGQAlxqSAF8SQWwhLYoc/AL8kYHyCDKpnWcvvJuy9UhqXA+Vnf9151
         MW2lJzjgElhnKjthLnta9TJiCa3s7TQwZXwfpuNiwqeDhG93qjbEJRbxBIeNWRH73ygI
         CDTcPia9gXQ7vk64kdYb8vYjZ4uyge1AKDvXjHUTH2HvgTPsNgQefNnrHzJqOh5MfYwf
         Jq8qqTkF/njh6GEu2oRloHzoRTOvMLUChnvaiiOWyTpOnDBbGcUy35zDRqn9t311G9BS
         TrrTEjLs9DP6cnphhW259eoUdE/DM29LZzabm0pGTce36VsoJxxBCxtk+19VmEo3ExS9
         h43A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=9g5UAE2SjxfDrTvNcmsOvc5raZR96mJY6wr+vR+2NDs=;
        b=aKG/3EIaodk/lRir2g0gEn75Y9MNwClQinFL3mnOqE4sZ27OFwXD60a8DDvu80B05j
         ZwewakwCjukh/uuK8HD8RoosdG19J3w91GtVQXY+eOdkfwpvGpVVc9+xF4J5zVAe57nU
         SqQy77aTz95fo/hUC7hlkPjFV5OXNM+Dt1j/Hjc/osNAfCY17rmJGTfFjFDsx/9m/A7m
         U/DrsgQL2UqNfsqI5O4OiyTvbuMmiVd0z6aKH53ms1n0A7fFqQ3O+q96vH1cz+5R/eSA
         vzYfTw2TVsU4dKpkFIj1Ub1Bt6nHqreYJS7QYtK9kYH2GY9CV+fVjwP2Gwkx2Ck3LMe9
         zYlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=a5VDk9Ml;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id f4si2177677otc.2.2021.05.22.19.38.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 May 2021 19:38:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id lx17-20020a17090b4b11b029015f3b32b8dbso7562666pjb.0
        for <kasan-dev@googlegroups.com>; Sat, 22 May 2021 19:38:32 -0700 (PDT)
X-Received: by 2002:a17:902:dccc:b029:f1:c207:b10b with SMTP id t12-20020a170902dcccb02900f1c207b10bmr19317352pll.41.1621737511695;
        Sat, 22 May 2021 19:38:31 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id v22sm7402355pff.105.2021.05.22.19.38.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 22 May 2021 19:38:31 -0700 (PDT)
Date: Sat, 22 May 2021 19:38:31 -0700 (PDT)
Subject: Re: [PATCH RFC v2] riscv: Enable KFENCE for riscv64
In-Reply-To: <CANpmjNMN2xQ28nsqUzE+XJ_muHUT+EGdCTCDhvLH2hMMxuTidQ@mail.gmail.com>
CC: liushixin2@huawei.com, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, glider@google.com, dvyukov@google.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: elver@google.com
Message-ID: <mhng-f2825fd1-15e0-403d-b972-d327494525e6@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=a5VDk9Ml;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 14 May 2021 08:20:10 PDT (-0700), elver@google.com wrote:
> On Fri, 14 May 2021 at 05:11, Liu Shixin <liushixin2@huawei.com> wrote:
>> Add architecture specific implementation details for KFENCE and enable
>> KFENCE for the riscv64 architecture. In particular, this implements the
>> required interface in <asm/kfence.h>.
>>
>> KFENCE requires that attributes for pages from its memory pool can
>> individually be set. Therefore, force the kfence pool to be mapped at
>> page granularity.
>>
>> I tested this patch using the testcases in kfence_test.c and all passed.
>>
>> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
>
> Acked-by: Marco Elver <elver@google.com>
>
>
>> ---
>> v1->v2: Change kmalloc() to pte_alloc_one_kernel() for allocating pte.
>>
>>  arch/riscv/Kconfig              |  1 +
>>  arch/riscv/include/asm/kfence.h | 51 +++++++++++++++++++++++++++++++++
>>  arch/riscv/mm/fault.c           | 11 ++++++-
>>  3 files changed, 62 insertions(+), 1 deletion(-)
>>  create mode 100644 arch/riscv/include/asm/kfence.h
>>
>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> index c426e7d20907..000d8aba1030 100644
>> --- a/arch/riscv/Kconfig
>> +++ b/arch/riscv/Kconfig
>> @@ -64,6 +64,7 @@ config RISCV
>>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>         select HAVE_ARCH_KASAN if MMU && 64BIT
>>         select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>> +       select HAVE_ARCH_KFENCE if MMU && 64BIT
>>         select HAVE_ARCH_KGDB
>>         select HAVE_ARCH_KGDB_QXFER_PKT
>>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
>> new file mode 100644
>> index 000000000000..c25d67e0b8ba
>> --- /dev/null
>> +++ b/arch/riscv/include/asm/kfence.h
>> @@ -0,0 +1,51 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +
>> +#ifndef _ASM_RISCV_KFENCE_H
>> +#define _ASM_RISCV_KFENCE_H
>> +
>> +#include <linux/kfence.h>
>> +#include <linux/pfn.h>
>> +#include <asm-generic/pgalloc.h>
>> +#include <asm/pgtable.h>
>> +
>> +static inline bool arch_kfence_init_pool(void)
>> +{
>> +       int i;
>> +       unsigned long addr;
>> +       pte_t *pte;
>> +       pmd_t *pmd;
>> +
>> +       for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
>> +            addr += PAGE_SIZE) {
>> +               pte = virt_to_kpte(addr);
>> +               pmd = pmd_off_k(addr);
>> +
>> +               if (!pmd_leaf(*pmd) && pte_present(*pte))
>> +                       continue;
>> +
>> +               pte = pte_alloc_one_kernel(&init_mm);
>> +               for (i = 0; i < PTRS_PER_PTE; i++)
>> +                       set_pte(pte + i, pfn_pte(PFN_DOWN(__pa((addr & PMD_MASK) + i * PAGE_SIZE)), PAGE_KERNEL));
>> +
>> +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
>> +               flush_tlb_kernel_range(addr, addr + PMD_SIZE);
>> +       }
>> +
>> +       return true;
>> +}

I'm not fundamentally opposed to this, but the arm64 approach where 
pages are split at runtime when they have mis-matched permissions seems 
cleaner to me.  I'm not sure why x86 is doing it during init, though, as 
IIUC set_memory_4k() will work for both.

Upgrading our __set_memory() with the ability to split pages (like arm64 
has) seems generally useful, and would let us trivially implement the 
dynamic version of this.  We'll probably end up with the ability to 
split pages anyway, so that would be the least code in the long run.

If there's some reason to prefer statically allocating the pages I'm 
fine with this, though.

>> +
>> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
>> +{
>> +       pte_t *pte = virt_to_kpte(addr);
>> +
>> +       if (protect)
>> +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
>> +       else
>> +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>> +
>> +       flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
>> +
>> +       return true;
>> +}
>> +
>> +#endif /* _ASM_RISCV_KFENCE_H */
>> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
>> index 096463cc6fff..aa08dd2f8fae 100644
>> --- a/arch/riscv/mm/fault.c
>> +++ b/arch/riscv/mm/fault.c
>> @@ -14,6 +14,7 @@
>>  #include <linux/signal.h>
>>  #include <linux/uaccess.h>
>>  #include <linux/kprobes.h>
>> +#include <linux/kfence.h>
>>
>>  #include <asm/ptrace.h>
>>  #include <asm/tlbflush.h>
>> @@ -45,7 +46,15 @@ static inline void no_context(struct pt_regs *regs, unsigned long addr)
>>          * Oops. The kernel tried to access some bad page. We'll have to
>>          * terminate things with extreme prejudice.
>>          */
>> -       msg = (addr < PAGE_SIZE) ? "NULL pointer dereference" : "paging request";
>> +       if (addr < PAGE_SIZE)
>> +               msg = "NULL pointer dereference";
>> +       else {
>> +               if (kfence_handle_page_fault(addr, regs->cause == EXC_STORE_PAGE_FAULT, regs))
>> +                       return;
>> +
>> +               msg = "paging request";
>> +       }
>> +
>>         die_kernel_fault(msg, addr, regs);
>>  }
>>
>> --
>> 2.18.0.huawei.25
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-f2825fd1-15e0-403d-b972-d327494525e6%40palmerdabbelt-glaptop.
