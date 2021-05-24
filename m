Return-Path: <kasan-dev+bncBAABBTMPVSCQMGQEWPJM56A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id BA14E38DF03
	for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 03:56:30 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id r25-20020a05620a03d9b02903a58bfe037csf19168951qkm.15
        for <lists+kasan-dev@lfdr.de>; Sun, 23 May 2021 18:56:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621821390; cv=pass;
        d=google.com; s=arc-20160816;
        b=mY5h5FrHFDgeDbOMyFBviYxiZgj1ErFlH7XdQqqjWYdGx/shHHPnqDjUcJtW3Dl3L5
         8dAyMKxlaOF/J0aHfgTU7Pr19EYxinxwHobb8VPa2ybgE81tiexL1Ajp+pwjLR8ux27n
         eWRkWTg2KFbsLsxTlwwwXITrK4PTgnFXNyb78Y2DhrDy7eUvlJory5fWDzp+W6cz6oPI
         EctfuHRaSLcL+c4Vpi5GIiRMCsNtU8Cb04rhaknbHTlLVYK4cHrWbB46m7cqxcdyZuDm
         4ohbg1UDmQM+kdjT5okGEQtpundc611qy5I+ARQUThGFRlZxkg19V7UD3knj7vKqvSYU
         eYHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:mime-version:user-agent:date:message-id:from:cc
         :references:to:subject:sender:dkim-signature;
        bh=LJRee5bKj7KbMIWQo/IXR1IOAF5fOlB2ZFdxRcTISBs=;
        b=Tm/HJKlsR2bjtrHXDTDd/ebtn95Kaaf4fOTPF2ZJlyr/8yML3XWkwwdIWnOP7Ae1cS
         LSomDr6ywpD+p8mRaQMavUlWUl5Je55x6TDSN2pT/NJOwS7PLZ+shCQNx/ewNZLknIy/
         vHExB5QoJe71xhKdoDG6fx+aI/D2NpKflZ/0QTwHhsvSazEj/B8MukMMe3370/nUxE+n
         CLDn7spvK42Xvgyy9Nx8ZlupT8dd+uKTQySZ/lgONR76JZWpQ9fwqepLcZJiVvORbylB
         EQGSX0NM198gFe3ToZ2JYadpPya2uXRqoXFB+lmYxhOcDv65frlvgMe6pdNEnFMUNI+2
         6ojw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LJRee5bKj7KbMIWQo/IXR1IOAF5fOlB2ZFdxRcTISBs=;
        b=HWfow8kzRpZGlob3oGGo34CMtgwqGexeGMX0u/tDf0puD++OgZx7RwgNGmYHIvv0fR
         aUuy5pJXFgkGVoy2SBj9uFZndTksUdpVF9Tc/tEKXUTgpUo0mQbixjU8zrvmbLubA6rd
         BofMYx6LSklFCyOCPLx2CcGzeRCWU8fY0iHnGTLJpwwWSh9k7+xYpPUsn6siWcgvlJAS
         OUnKXzc3IEUwnW8wEax1KM7PInFNwNPwbZhrW9MWyfRSfJe8GhdtyeDKiuOP471aLnma
         Q0hhtjTb1w2gx2YCR542YhlAP19G/uyzjAlzJM6gwD3ka6qwJ4v6gnkMHAuAOd5uh8F4
         8GKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LJRee5bKj7KbMIWQo/IXR1IOAF5fOlB2ZFdxRcTISBs=;
        b=Aeuzfkg30M3gpyTgshGub8AgWnxBwbqwsP2oZnaUHTldRL5wj2TVeVaZopZ49uuEGN
         svTquhemSmfOv7FRiU6uADbmuC/6+Xh290yk9rFAs/aVczXY6Xl+qvMLnlsi3NT1FwBc
         8xwM1K6H6C2jbKQCD2Wg8web4WFGEYraIajP2JORDi1sg26QKWJDm3tvBJpZeK8vRR0K
         g1xKgAwmeNoC9Fta11yRLS0Hd0GLVqCGHxCQg5Ql5eRMSVMXCMHizsssNx5HHbxtMPzn
         VS+2bGsnlFWTCSR/BrdD6Bpq2mjyAi8c9LmyLo1HOPlUg63fstFuV/R4weoalxwEfsPF
         4EUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rfLwZQ94BpfpWk7OBETqLdeVnfJkYQ7e4S8+yqZXwwTQOmIc7
	MhtdCzWcFLvFTjN3p/+MMPY=
X-Google-Smtp-Source: ABdhPJxS7/ovJzPaf5QAKcz2gpCusIg7OQv7wlP/tGsJTMe4f/PIAS1JDuc4vk1EEqatf8/aoHNknw==
X-Received: by 2002:a37:ae04:: with SMTP id x4mr25142732qke.315.1621821389889;
        Sun, 23 May 2021 18:56:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:8cd:: with SMTP id da13ls3841196qvb.0.gmail; Sun,
 23 May 2021 18:56:29 -0700 (PDT)
X-Received: by 2002:ad4:4d4e:: with SMTP id m14mr27763793qvm.50.1621821389553;
        Sun, 23 May 2021 18:56:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621821389; cv=none;
        d=google.com; s=arc-20160816;
        b=vMe50ZvR/iTuDxzcHHCEFfHPZVrMjSw2qthNYMJV/E6+yRXmex5jrW9f3F3wOQXLdL
         iCIxSOn/ObtBxvNdobJqVZLa2wd9FOmVVuxmfJ1zHuBBc8oggCFKfw0bgjSlE1z5uj4i
         MIkQfZb3M8UocOcqjSuUh8lK7TO1sg1nmTs0p/n+8dI3+LqSnLf45Wt+PrwwyKhsHYP5
         wIo72TuK4bh5hOaYxaw4oqNABq8Ezwwe2QlDyekquwEFr4vQmWZxxuYobTvrfTAos0FF
         fUSoThyvCEIv0+AEHrzQHOhlUl6pLWhKcYzVC0aQl4/votfXSbgiNOBjMTly7UStxXoQ
         xN1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=56qe0/kRnakHJ8F8HYYM4CTdtFKZseEcuy2AVnKEd/4=;
        b=cMOB+SvXIxos5Wo6fb0+lAFPIFNs0OgdLUkhUi5fUn1e2+Xqv+CNAcWEyhvt+1scD9
         uN6iufTSv0KdLZ9SXGFxP7lE9Ik6jVXD5pL85napAhqqsEhfLqkd8VPNV8PJB03lh8/0
         VkCZD2BGOMj+Iy3295MxqUOFGU/hyAmep4DPnWbkFq4uBucfojABFy0gYnPOsy9s1fK/
         /aIHSz3LvN5aTUKRn99QmvEthm3WkVKNmY93sXrx/wAnyjGtDKCUCE+duSRvuZMaUsJV
         wG3Jag1e+rETkWQiZ2sqrHIZoWVdPz5iJXlRMAJ1VwKshcob8kFuJnkhDI4rBjZupspF
         EimQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id t11si1276818qto.3.2021.05.23.18.56.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 May 2021 18:56:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from dggems705-chm.china.huawei.com (unknown [172.30.72.59])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4FpKwg3wLFzncSx;
	Mon, 24 May 2021 09:52:51 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggems705-chm.china.huawei.com (10.3.19.182) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 24 May 2021 09:56:26 +0800
Received: from [10.174.179.24] (10.174.179.24) by
 dggpemm500009.china.huawei.com (7.185.36.225) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 24 May 2021 09:56:25 +0800
Subject: Re: [PATCH RFC v2] riscv: Enable KFENCE for riscv64
To: Palmer Dabbelt <palmer@dabbelt.com>, <elver@google.com>
References: <mhng-f2825fd1-15e0-403d-b972-d327494525e6@palmerdabbelt-glaptop>
CC: Paul Walmsley <paul.walmsley@sifive.com>, <aou@eecs.berkeley.edu>,
	<glider@google.com>, <dvyukov@google.com>, <linux-riscv@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
From: Liu Shixin <liushixin2@huawei.com>
Message-ID: <0b584a85-79e2-fcdd-2adf-5b63f56cc591@huawei.com>
Date: Mon, 24 May 2021 09:56:24 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <mhng-f2825fd1-15e0-403d-b972-d327494525e6@palmerdabbelt-glaptop>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.24]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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



On 2021/5/23 10:38, Palmer Dabbelt wrote:
> On Fri, 14 May 2021 08:20:10 PDT (-0700), elver@google.com wrote:
>> On Fri, 14 May 2021 at 05:11, Liu Shixin <liushixin2@huawei.com> wrote:
>>> Add architecture specific implementation details for KFENCE and enable
>>> KFENCE for the riscv64 architecture. In particular, this implements the
>>> required interface in <asm/kfence.h>.
>>>
>>> KFENCE requires that attributes for pages from its memory pool can
>>> individually be set. Therefore, force the kfence pool to be mapped at
>>> page granularity.
>>>
>>> I tested this patch using the testcases in kfence_test.c and all passed=
.
>>>
>>> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
>>
>> Acked-by: Marco Elver <elver@google.com>
>>
>>
>>> ---
>>> v1->v2: Change kmalloc() to pte_alloc_one_kernel() for allocating pte.
>>>
>>>  arch/riscv/Kconfig              |  1 +
>>>  arch/riscv/include/asm/kfence.h | 51 +++++++++++++++++++++++++++++++++
>>>  arch/riscv/mm/fault.c           | 11 ++++++-
>>>  3 files changed, 62 insertions(+), 1 deletion(-)
>>>  create mode 100644 arch/riscv/include/asm/kfence.h
>>>
>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>> index c426e7d20907..000d8aba1030 100644
>>> --- a/arch/riscv/Kconfig
>>> +++ b/arch/riscv/Kconfig
>>> @@ -64,6 +64,7 @@ config RISCV
>>>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>>         select HAVE_ARCH_KASAN if MMU && 64BIT
>>>         select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>>> +       select HAVE_ARCH_KFENCE if MMU && 64BIT
>>>         select HAVE_ARCH_KGDB
>>>         select HAVE_ARCH_KGDB_QXFER_PKT
>>>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>>> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/k=
fence.h
>>> new file mode 100644
>>> index 000000000000..c25d67e0b8ba
>>> --- /dev/null
>>> +++ b/arch/riscv/include/asm/kfence.h
>>> @@ -0,0 +1,51 @@
>>> +/* SPDX-License-Identifier: GPL-2.0 */
>>> +
>>> +#ifndef _ASM_RISCV_KFENCE_H
>>> +#define _ASM_RISCV_KFENCE_H
>>> +
>>> +#include <linux/kfence.h>
>>> +#include <linux/pfn.h>
>>> +#include <asm-generic/pgalloc.h>
>>> +#include <asm/pgtable.h>
>>> +
>>> +static inline bool arch_kfence_init_pool(void)
>>> +{
>>> +       int i;
>>> +       unsigned long addr;
>>> +       pte_t *pte;
>>> +       pmd_t *pmd;
>>> +
>>> +       for (addr =3D (unsigned long)__kfence_pool; is_kfence_address((=
void *)addr);
>>> +            addr +=3D PAGE_SIZE) {
>>> +               pte =3D virt_to_kpte(addr);
>>> +               pmd =3D pmd_off_k(addr);
>>> +
>>> +               if (!pmd_leaf(*pmd) && pte_present(*pte))
>>> +                       continue;
>>> +
>>> +               pte =3D pte_alloc_one_kernel(&init_mm);
>>> +               for (i =3D 0; i < PTRS_PER_PTE; i++)
>>> +                       set_pte(pte + i, pfn_pte(PFN_DOWN(__pa((addr & =
PMD_MASK) + i * PAGE_SIZE)), PAGE_KERNEL));
>>> +
>>> +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
>>> +               flush_tlb_kernel_range(addr, addr + PMD_SIZE);
>>> +       }
>>> +
>>> +       return true;
>>> +}
>
> I'm not fundamentally opposed to this, but the arm64 approach where pages=
 are split at runtime when they have mis-matched permissions seems cleaner =
to me.  I'm not sure why x86 is doing it during init, though, as IIUC set_m=
emory_4k() will work for both.
>
> Upgrading our __set_memory() with the ability to split pages (like arm64 =
has) seems generally useful, and would let us trivially implement the dynam=
ic version of this.  We'll probably end up with the ability to split pages =
anyway, so that would be the least code in the long run.
>
> If there's some reason to prefer statically allocating the pages I'm fine=
 with this, though.
>
As I understand=EF=BC=8Cthe arm64 approach does not implement dynamic split=
ting.
If kfence is enabled in arch arm64, the linear map need to be forcibly mapp=
ed
at page granularity. But x86 does not have such constraints as it only spli=
t pages
in the kfence pool, so I think the x86 approach is better as it has less in=
fluence
on the whole.
>>> +
>>> +static inline bool kfence_protect_page(unsigned long addr, bool protec=
t)
>>> +{
>>> +       pte_t *pte =3D virt_to_kpte(addr);
>>> +
>>> +       if (protect)
>>> +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
>>> +       else
>>> +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>>> +
>>> +       flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
>>> +
>>> +       return true;
>>> +}
>>> +
>>> +#endif /* _ASM_RISCV_KFENCE_H */
>>> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
>>> index 096463cc6fff..aa08dd2f8fae 100644
>>> --- a/arch/riscv/mm/fault.c
>>> +++ b/arch/riscv/mm/fault.c
>>> @@ -14,6 +14,7 @@
>>>  #include <linux/signal.h>
>>>  #include <linux/uaccess.h>
>>>  #include <linux/kprobes.h>
>>> +#include <linux/kfence.h>
>>>
>>>  #include <asm/ptrace.h>
>>>  #include <asm/tlbflush.h>
>>> @@ -45,7 +46,15 @@ static inline void no_context(struct pt_regs *regs, =
unsigned long addr)
>>>          * Oops. The kernel tried to access some bad page. We'll have t=
o
>>>          * terminate things with extreme prejudice.
>>>          */
>>> -       msg =3D (addr < PAGE_SIZE) ? "NULL pointer dereference" : "pagi=
ng request";
>>> +       if (addr < PAGE_SIZE)
>>> +               msg =3D "NULL pointer dereference";
>>> +       else {
>>> +               if (kfence_handle_page_fault(addr, regs->cause =3D=3D E=
XC_STORE_PAGE_FAULT, regs))
>>> +                       return;
>>> +
>>> +               msg =3D "paging request";
>>> +       }
>>> +
>>>         die_kernel_fault(msg, addr, regs);
>>>  }
>>>
>>> --=20
>>> 2.18.0.huawei.25
>>>
>
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0b584a85-79e2-fcdd-2adf-5b63f56cc591%40huawei.com.
