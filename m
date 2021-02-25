Return-Path: <kasan-dev+bncBAABBNWT3WAQMGQE5WAVHVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 813A1324C72
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 10:11:20 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id b4sf461554vsb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 01:11:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614244279; cv=pass;
        d=google.com; s=arc-20160816;
        b=jsepEGtbg5LeypaktCb9f22w4vyENq0bOqkBf6tadxSejzVyZEo+tbiaSdZl+fUgZ7
         q3EsxoxD/c/xcNdChymMkjuXYOD1QbQQIbZ+yLW3ikrCltRsTdr8zstw4mGomho7tDU1
         iA1BTsBAUri1tELJcilULfEmFUn0DNJLSfP4mYrmsqGWx2tAwj/p5BrZamAOyuKqJmg6
         Oy9RKdgiECQ8dPogQlfzMbzZnNtm3MLnTPvzTi4nkdMx+MzKax41VRcHMK4/nl3/UBVo
         OmvKGewtbNfqIftV+joUu603eIV42D2qIWJUlVeEoHB/yQG7sKuVUmml7cowbplYMnnN
         84Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=5gnWtZToc99gNjsIayB1Jab6oiwslAPX+3KqbjM7DUg=;
        b=S6XQHXKks1Dj72UsekXafR82o7irpoFEijBSdbEQZ3FUoAk2FJ3HbBNhmYzQNkX2sg
         pmlE3/6l8s+GTBO0+tSdrEwzyJXAhuKLmjvHrEY7HZwsgncqPn/b6fVPcjGB/GTHBcFZ
         BKNBv8JXg9+6YC+wvGO96EFb6+fy9KTJLff48AbV7epXpQey5xhbo2JCdXOS/VhPOMO9
         5pSxkHZC60X3uz1P75HR8zFiQ37R8qEk4F6zqTof1l8rbm1EhHYjb09FvTCKDBMaxhh9
         3RWmmrQoScdOMTlIzijs+mZeAHfGHqRIn2Fq5QQ384g2nOs24npA5byAvWz8agZdyGZI
         +Fsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5gnWtZToc99gNjsIayB1Jab6oiwslAPX+3KqbjM7DUg=;
        b=LAT/p7F7A0bmSYJFTRtWnDtKrlpyXvQl+3rk370jYmBn/4izcij5WC1L+otgsHdyzB
         ZMcTG96E+AWZpPKYTxdanh7qUzEolV/q06D3/sZ/8sbDn3PMG8otefPSQzBvwYmj+M+E
         vYsjLYZl2FhT5MarxIukH6T+UiBpTDvzVtrbCBsQDtdmRRMeqvB6fFO0OiXxZmN3GxbX
         D1LgnkSPcfqfL5rIB8Sirn/FknA6eza3/0I28Uig1HRgofXlOEW+FApRNH6WzSiCaeUH
         bB+dkSvt7y69KNmIYzsZ9NsLAaF9vWx9OzNw26OwTkRbs53/tz1tOS7+zIyK2CkB9D9+
         o94A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5gnWtZToc99gNjsIayB1Jab6oiwslAPX+3KqbjM7DUg=;
        b=egJakOE5PGWhJeHu609luZB3xtcvtUSbnZ4c/6v0rTKyDSIj21QQRURauvXTE6Rirn
         8i5UI+2xdljDMlQIgQCmSCl/wf4DJreVBGk6BYPfnCGsVCAhK7wPOsROY2S9vzHby7BJ
         EGcowil8OnZ48kw48crq/WIp7hrCjWaJ0h712ygevLzYddmT6s9xu7EMfn2NtQhLZYWF
         +DLac6CZ4Fwenbpw38UQ/zeY+n4bve2N1fAP8qgLtHuUsxQ+2veByaUckdXYCCyW8XH5
         bxxE/W2SUClga0Ui1MEMZLIBZdbwFu9j6otOZyrqzi7TLjhR2IxJjsARN9FniiJOWWSu
         yfvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322HibYJI/mURYiiD8hhkBpmZh+Y9IISw+7hBlzrKA/OnOg1YXw
	ERIIGZyBjk4gzwYdToEMoMg=
X-Google-Smtp-Source: ABdhPJxa8bHg5kZCHuusDreJHEvL9fFzgVODuP0xeOEPR+SZShBkVoACf9M5y2/rN8tmObl2Hxi0gQ==
X-Received: by 2002:a1f:180c:: with SMTP id 12mr817806vky.24.1614244279235;
        Thu, 25 Feb 2021 01:11:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:5d47:: with SMTP id r68ls580149vsb.10.gmail; Thu, 25 Feb
 2021 01:11:18 -0800 (PST)
X-Received: by 2002:a67:384:: with SMTP id 126mr999126vsd.40.1614244278557;
        Thu, 25 Feb 2021 01:11:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614244278; cv=none;
        d=google.com; s=arc-20160816;
        b=h+lKAqOWBtN8VDVb4rLQIaMQv5B2SvrlIRmXgaOmqrVRvjpFLR+22MrjqC8Ghkn48P
         7+G98LINqMHCFUOQGTGu5FBmi4Kg/KOpx+hqfp0rgkqdEq+Kl2YgnGk2fJ91jIaAK9ff
         f6goUSa80wibNyX4dPD+iHOmB59zobC7vuQp8RbRj9YeNgKnXNP6nAjNufF23GTD5cb7
         2kKnnp81SFLBwB6CRN/hD7VJV2U1iyJCSSAps9cppF1b5LZGq3Wef3GLL4lHpkHURd0O
         aTPivJTk9O11e5majMSBDjo/qaM3WKN57YAfm3IYwRCGTblGWCL3cUGqiAMaNRT3GqeP
         YquQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=uebb8Olnqx6illzXtq/HGpBElWcP4DscFtVeE06xGmo=;
        b=H8zDLnKGBYXIkR9wmRfVDQLHwh5+dup5aTDKl5BZQMiCjU4zw4rX35mgcbgKAk/s75
         FfPWg8+JrdCwkvASnFvVsBopjBex2EPVVFw/F5MqnkjrvdibiDnrhmDnHjkL3tfB22e8
         5vDKWt7jLPQaqztThmrnGJTPgWRp1a55tqs+qbuqxQH5iwhCwoDyDHL18DPQo5GBeqBA
         6wHyFAmObjQZ2YyVVGqsHcl9AIrClDOYLgKUu4o0zdC64yyJgi4w8ggVu6k6jJXPyESG
         2SKAG5pAMOI42I2jJYOTQU+W4TCi8JGymIUTP+27urs3L32LEJ8ppaXuAoEUDk6s/711
         jeGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (atcsqr.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id a24si165631vsh.2.2021.02.25.01.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 01:11:18 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 11P94pVw011628;
	Thu, 25 Feb 2021 17:04:51 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcfdc88 (10.0.15.120) by ATCPCS16.andestech.com (10.0.1.222)
 with Microsoft SMTP Server id 14.3.487.0; Thu, 25 Feb 2021 17:10:34 +0800
Date: Thu, 25 Feb 2021 17:10:35 +0800
From: Nylon Chen <nylon7@andestech.com>
To: Alex Ghiti <alex@ghiti.fr>
CC: "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "Nick Chun-Ming
 Hu(?????????)" <nickhu@andestech.com>,
        "Alan Quey-Liang Kao(?????????)"
	<alankao@andestech.com>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        "nylon7717@gmail.com" <nylon7717@gmail.com>,
        "aryabinin@virtuozzo.com" <aryabinin@virtuozzo.com>,
        Palmer Dabbelt
	<palmer@dabbelt.com>,
        Paul Walmsley <paul.walmsley@sifive.com>,
        "glider@google.com" <glider@google.com>,
        "linux-riscv@lists.infradead.org"
	<linux-riscv@lists.infradead.org>,
        "dvyukov@google.com" <dvyukov@google.com>
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
Message-ID: <20210225091035.GA12748@atcfdc88>
References: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
 <2b2f3038-3e27-8763-cf78-3fbbfd2100a0@ghiti.fr>
 <4fa97788-157c-4059-ae3f-28ab074c5836@ghiti.fr>
 <e15fbf55-25db-7f91-6feb-fb081ab60cdb@ghiti.fr>
 <20210222013754.GA7626@andestech.com>
 <af58ed3d-36e4-1278-dc42-7df2d875abbc@ghiti.fr>
 <42483a2b-efb9-88a8-02b2-9f44eed3d418@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <42483a2b-efb9-88a8-02b2-9f44eed3d418@ghiti.fr>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Originating-IP: [10.0.15.120]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 11P94pVw011628
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

Hi Alex, Palmer
On Thu, Feb 25, 2021 at 03:11:07AM +0800, Alex Ghiti wrote:
> Hi Nylon,
> 
> Le 2/22/21 ?? 12:13 PM, Alex Ghiti a ??crit??:
> > Le 2/21/21 ?? 8:37 PM, Nylon Chen a ??crit??:
> >> Hi Alex, Palmer
> >>
> >> Sorry I missed this message.
> >> On Sun, Feb 21, 2021 at 09:38:04PM +0800, Alex Ghiti wrote:
> >>> Le 2/13/21 ?? 5:52 AM, Alex Ghiti a ??crit??:
> >>>> Hi Nylon, Palmer,
> >>>>
> >>>> Le 2/8/21 ?? 1:28 AM, Alex Ghiti a ??crit??:
> >>>>> Hi Nylon,
> >>>>>
> >>>>> Le 1/22/21 ?? 10:56 PM, Palmer Dabbelt a ??crit??:
> >>>>>> On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote:
> >>>>>>> It references to x86/s390 architecture.
> >>>>>>>>> So, it doesn't map the early shadow page to cover VMALLOC space.
> >>>>>>>
> >>>>>>> Prepopulate top level page table for the range that would 
> >>>>>>> otherwise be
> >>>>>>> empty.
> >>>>>>>
> >>>>>>> lower levels are filled dynamically upon memory allocation while
> >>>>>>> booting.
> >>>>>
> >>>>> I think we can improve the changelog a bit here with something like 
> >>>>> that:
> >>>>>
> >>>>> "KASAN vmalloc space used to be mapped using kasan early shadow page.
> >>>>> KASAN_VMALLOC requires the top-level of the kernel page table to be
> >>>>> properly populated, lower levels being filled dynamically upon memory
> >>>>> allocation at runtime."
> >>>>>
> >>>>>>>
> >>>>>>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
> >>>>>>> Signed-off-by: Nick Hu <nickhu@andestech.com>
> >>>>>>> ---
> >>>>>>> ????arch/riscv/Kconfig???????????????? |?? 1 +
> >>>>>>> ????arch/riscv/mm/kasan_init.c | 57 
> >>>>>>> +++++++++++++++++++++++++++++++++++++-
> >>>>>>> ????2 files changed, 57 insertions(+), 1 deletion(-)
> >>>>>>>
> >>>>>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> >>>>>>> index 81b76d44725d..15a2c8088bbe 100644
> >>>>>>> --- a/arch/riscv/Kconfig
> >>>>>>> +++ b/arch/riscv/Kconfig
> >>>>>>> @@ -57,6 +57,7 @@ config RISCV
> >>>>>>> ?????????? select HAVE_ARCH_JUMP_LABEL
> >>>>>>> ?????????? select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >>>>>>> ?????????? select HAVE_ARCH_KASAN if MMU && 64BIT
> >>>>>>> +?????? select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
> >>>>>>> ?????????? select HAVE_ARCH_KGDB
> >>>>>>> ?????????? select HAVE_ARCH_KGDB_QXFER_PKT
> >>>>>>> ?????????? select HAVE_ARCH_MMAP_RND_BITS if MMU
> >>>>>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> >>>>>>> index 12ddd1f6bf70..4b9149f963d3 100644
> >>>>>>> --- a/arch/riscv/mm/kasan_init.c
> >>>>>>> +++ b/arch/riscv/mm/kasan_init.c
> >>>>>>> @@ -9,6 +9,19 @@
> >>>>>>> ????#include <linux/pgtable.h>
> >>>>>>> ????#include <asm/tlbflush.h>
> >>>>>>> ????#include <asm/fixmap.h>
> >>>>>>> +#include <asm/pgalloc.h>
> >>>>>>> +
> >>>>>>> +static __init void *early_alloc(size_t size, int node)
> >>>>>>> +{
> >>>>>>> +?????? void *ptr = memblock_alloc_try_nid(size, size,
> >>>>>>> +?????????????? __pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
> >>>>>>> +
> >>>>>>> +?????? if (!ptr)
> >>>>>>> +?????????????? panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d
> >>>>>>> from=%llx\n",
> >>>>>>> +?????????????????????? __func__, size, size, node, 
> >>>>>>> (u64)__pa(MAX_DMA_ADDRESS));
> >>>>>>> +
> >>>>>>> +?????? return ptr;
> >>>>>>> +}
> >>>>>>>
> >>>>>>> ????extern pgd_t early_pg_dir[PTRS_PER_PGD];
> >>>>>>> ????asmlinkage void __init kasan_early_init(void)
> >>>>>>> @@ -83,6 +96,40 @@ static void __init populate(void *start, void 
> >>>>>>> *end)
> >>>>>>> ?????????? memset(start, 0, end - start);
> >>>>>>> ????}
> >>>>>>>
> >>>>>>> +void __init kasan_shallow_populate(void *start, void *end)
> >>>>>>> +{
> >>>>>>> +?????? unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> >>>>>>> +?????? unsigned long vend = PAGE_ALIGN((unsigned long)end);
> >>>>>>> +?????? unsigned long pfn;
> >>>>>>> +?????? int index;
> >>>>>>> +?????? void *p;
> >>>>>>> +?????? pud_t *pud_dir, *pud_k;
> >>>>>>> +?????? pgd_t *pgd_dir, *pgd_k;
> >>>>>>> +?????? p4d_t *p4d_dir, *p4d_k;
> >>>>>>> +
> >>>>>>> +?????? while (vaddr < vend) {
> >>>>>>> +?????????????? index = pgd_index(vaddr);
> >>>>>>> +?????????????? pfn = csr_read(CSR_SATP) & SATP_PPN;
> >>>>>
> >>>>> At this point in the boot process, we know that we use swapper_pg_dir
> >>>>> so no need to read SATP.
> >>>>>
> >>>>>>> +?????????????? pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
> >>>>>
> >>>>> Here, this pgd_dir assignment is overwritten 2 lines below, so no need
> >>>>> for it.
> >>>>>
> >>>>>>> +?????????????? pgd_k = init_mm.pgd + index;
> >>>>>>> +?????????????? pgd_dir = pgd_offset_k(vaddr);
> >>>>>
> >>>>> pgd_offset_k(vaddr) = init_mm.pgd + pgd_index(vaddr) so pgd_k == 
> >>>>> pgd_dir.
> >>>>>
> >>>>>>> +?????????????? set_pgd(pgd_dir, *pgd_k);
> >>>>>>> +
> >>>>>>> +?????????????? p4d_dir = p4d_offset(pgd_dir, vaddr);
> >>>>>>> +?????????????? p4d_k?? = p4d_offset(pgd_k, vaddr);
> >>>>>>> +
> >>>>>>> +?????????????? vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
> >>>>>
> >>>>> Why do you increase vaddr *before* populating the first one ? And
> >>>>> pud_addr_end does that properly: it returns the next pud address if it
> >>>>> does not go beyond end address to map.
> >>>>>
> >>>>>>> +?????????????? pud_dir = pud_offset(p4d_dir, vaddr);
> >>>>>>> +?????????????? pud_k = pud_offset(p4d_k, vaddr);
> >>>>>>> +
> >>>>>>> +?????????????? if (pud_present(*pud_dir)) {
> >>>>>>> +?????????????????????? p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> >>>>>>> +?????????????????????? pud_populate(&init_mm, pud_dir, p);
> >>>>>
> >>>>> init_mm is not needed here.
> >>>>>
> >>>>>>> +?????????????? }
> >>>>>>> +?????????????? vaddr += PAGE_SIZE;
> >>>>>
> >>>>> Why do you need to add PAGE_SIZE ? vaddr already points to the next 
> >>>>> pud.
> >>>>>
> >>>>> It seems like this patch tries to populate userspace page table
> >>>>> whereas at this point in the boot process, only swapper_pg_dir is used
> >>>>> or am I missing something ?
> >>>>>
> >>>>> Thanks,
> >>>>>
> >>>>> Alex
> >>>>
> >>>> I implemented this morning a version that fixes all the comments I made
> >>>> earlier. I was able to insert test_kasan_module on both sv39 and sv48
> >>>> without any modification: set_pgd "goes through" all the unused page
> >>>> table levels, whereas p*d_populate are noop for unused levels.
> >>>>
> >>>> If you have any comment, do not hesitate.
> >>>>
> >>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> >>>> index adbf94b7e68a..d643b222167c 100644
> >>>> --- a/arch/riscv/mm/kasan_init.c
> >>>> +++ b/arch/riscv/mm/kasan_init.c
> >>>> @@ -195,6 +195,31 @@ static void __init kasan_populate(void *start, 
> >>>> void
> >>>> *end)
> >>>> ?? ?????????????? memset(start, KASAN_SHADOW_INIT, end - start);
> >>>> ?? ??}
> >>>>
> >>>>
> >>>> +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned
> >>>> long end)
> >>>> +{
> >>>> +???????????? unsigned long next;
> >>>> +???????????? void *p;
> >>>> +???????????? pgd_t *pgd_k = pgd_offset_k(vaddr);
> >>>> +
> >>>> +???????????? do {
> >>>> +???????????????????????????? next = pgd_addr_end(vaddr, end);
> >>>> +???????????????????????????? if (pgd_page_vaddr(*pgd_k) == (unsigned
> >>>> long)lm_alias(kasan_early_shadow_pgd_next)) {
> >>>> +???????????????????????????????????????????? p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> >>>> +???????????????????????????????????????????? set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)),
> >>>> PAGE_TABLE));
> >>>> +???????????????????????????? }
> >>>> +???????????? } while (pgd_k++, vaddr = next, vaddr != end);
> >>>> +}
> >>>> +
> >>>
> >>> This way of going through the page table seems to be largely used across
> >>> the kernel (cf KASAN population functions of arm64/x86) so I do think
> >>> this patch brings value to Nylon and Nick's patch.
> >>>
> >>> I can propose a real patch if you agree and I'll add a co-developed by
> >>> Nylon/Nick since this only 'improves' theirs.
> >>>
> >>> Thanks,
> >>>
> >>> Alex
> >>>
> >> I agree with your proposal, but when I try your patch that it dosen't 
> >> work
> >> because `kasan_early_shadow_pgd_next` function wasn't define.
> > 
> > Oops, I messed up my rebase, please replace 
> > 'kasan_early_shadow_pgd_next' with 'kasan_early_shadow_pmd'.
> > 
> > Thank you for your feeback,
> > 
> > Alex
> > 
> 
> Did you have time to test the above fix ? It would be nice to replace 
> your current patch with the above solution before it gets merged for 
> 5.12, I will propose something tomorrow, feel free to review and test :)
> 
> Thanks again,
> 
> Alex
> 
Today I follow your fix in our platform, it's workable.

Thank you for your fix.
> >>
> >> Do you have complete patch? or just I missed some content?
> >>>> +void __init kasan_shallow_populate(void *start, void *end)
> >>>> +{
> >>>> +???????????? unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> >>>> +???????????? unsigned long vend = PAGE_ALIGN((unsigned long)end);
> >>>> +
> >>>> +???????????? kasan_shallow_populate_pgd(vaddr, vend);
> >>>> +
> >>>> +???????????? local_flush_tlb_all();
> >>>> +}
> >>>> +
> >>>> ?? ??void __init kasan_init(void)
> >>>> ?? ??{
> >>>> ?? ?????????????? phys_addr_t _start, _end;
> >>>> @@ -206,7 +231,15 @@ void __init kasan_init(void)
> >>>> ?? ???????????????? */
> >>>> ?? ?????????????? kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
> >>>> ?? ?????????????????????????????????????????????????????????????????????? (void 
> >>>> *)kasan_mem_to_shadow((void *)
> >>>> - VMALLOC_END));
> >>>> + VMEMMAP_END));
> >>>> +???????????? if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
> >>>> +???????????????????????????? kasan_shallow_populate(
> >>>> +???????????????????????????????????????????? (void *)kasan_mem_to_shadow((void 
> >>>> *)VMALLOC_START),
> >>>> +???????????????????????????????????????????? (void *)kasan_mem_to_shadow((void 
> >>>> *)VMALLOC_END));
> >>>> +???????????? else
> >>>> +???????????????????????????? kasan_populate_early_shadow(
> >>>> +???????????????????????????????????????????? (void *)kasan_mem_to_shadow((void 
> >>>> *)VMALLOC_START),
> >>>> +???????????????????????????????????????????? (void *)kasan_mem_to_shadow((void 
> >>>> *)VMALLOC_END));
> >>>>
> >>>>
> >>>> ?? ?????????????? /* Populate the linear mapping */
> >>>> ?? ?????????????? for_each_mem_range(i, &_start, &_end) {
> >>
> >> _______________________________________________
> >> linux-riscv mailing list
> >> linux-riscv@lists.infradead.org
> >> http://lists.infradead.org/mailman/listinfo/linux-riscv
> >>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210225091035.GA12748%40atcfdc88.
